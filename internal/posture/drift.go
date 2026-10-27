package posture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// Application drift (F-015 T-25; AC-36, AC-37; design §6.7; migration
// 0028). The database runs checks 1-3 (row MACs, bounds and exceptions,
// missed reverts); the engine adds check 4, comparing service heartbeats
// with the snapshot every service should enforce, and records the findings
// with their audit events in one transaction.

// Drift checks this engine owns. revert_failed belongs to the revert loop.
const (
	CheckRowMAC         = "row_mac_mismatch"
	CheckHardFloor      = "hard_floor_violation"
	CheckDeviation      = "unapproved_deviation"
	CheckMissedRevert   = "missed_revert"
	CheckSettingsMatch  = "settings_mismatch"
	CheckStaleCache     = "stale_settings_cache"
	DriftActor          = "system:posture-drift"
	defaultHBWindow     = 3 * time.Minute
	defaultStaleAfter   = 90 * time.Second
	defaultRevertGrace  = time.Minute
	defaultFullScanEach = 15 * time.Minute
)

var driftChecks = []string{CheckRowMAC, CheckHardFloor, CheckDeviation, CheckMissedRevert, CheckSettingsMatch, CheckStaleCache}

// Drift scans for application drift.
type Drift struct {
	DB    *pgxpool.Pool // app_posture
	Audit audit.Emitter
	// HeartbeatWindow is how recent a heartbeat must be to count (default
	// 3 minutes: three missed 60 s heartbeats mean the instance is gone).
	HeartbeatWindow time.Duration
	// StaleAfter is how long after a posture change a service may still
	// report the previous version (default 90 s: the 30 s poll plus a 60 s
	// heartbeat).
	StaleAfter time.Duration
	// RevertGrace is how long an expired exception may stay active before
	// it counts as a missed revert (default 1 minute; AC-28).
	RevertGrace time.Duration
}

// Finding is one drift finding. The JSON form is what a scan reports to
// posture.sync_drift_findings.
type Finding struct {
	ID          string          `json:"-"`
	Kind        string          `json:"-"` // app or deployment
	CheckID     string          `json:"check_id"`
	Severity    string          `json:"severity"`
	Controls    []string        `json:"controls"`
	Subject     string          `json:"subject"`
	Detail      json.RawMessage `json:"detail"`
	Remediation string          `json:"remediation"`
	// Lifecycle (T-26), from the database.
	Status            string     `json:"-"` // open, acknowledged or resolved
	AcknowledgedBy    string     `json:"-"`
	AcknowledgedAt    *time.Time `json:"-"`
	AcknowledgeReason string     `json:"-"`
	FirstSeen         time.Time  `json:"-"`
	LastSeen          time.Time  `json:"-"`
	ResolvedAt        *time.Time `json:"-"`
}

// eventAttrs are the attributes every drift event carries
// (drift_events.schema.json).
func (f Finding) eventAttrs() map[string]string {
	a := map[string]string{"finding_id": f.ID, "check_id": f.CheckID, "kind": f.Kind, "severity": f.Severity,
		"controls": strings.Join(f.Controls, ","), "subject": f.Subject}
	if len(f.Detail) > 0 {
		a["detail"] = string(f.Detail)
	}
	if f.Remediation != "" {
		a["remediation"] = f.Remediation
	}
	if f.AcknowledgedBy != "" {
		a["acknowledged_by"] = f.AcknowledgedBy
	}
	return a
}

// ScanResult reports a scan.
type ScanResult struct {
	Findings []Finding // in force after the scan, from the checks the scan ran
	Opened   []Finding
	Resolved []Finding
}

func (d Drift) withDefaults() Drift {
	if d.HeartbeatWindow <= 0 {
		d.HeartbeatWindow = defaultHBWindow
	}
	if d.StaleAfter <= 0 {
		d.StaleAfter = defaultStaleAfter
	}
	if d.RevertGrace <= 0 {
		d.RevertGrace = defaultRevertGrace
	}
	return d
}

// Scan runs every check and records the result: new findings are opened
// and audited (high, or critical), findings no longer seen are resolved and
// audited. If an audit event cannot be written, nothing is recorded.
func (d Drift) Scan(ctx context.Context) (ScanResult, error) {
	d = d.withDefaults()
	var res ScanResult
	rows, err := d.DB.Query(ctx, "SELECT check_id, severity, controls, subject, detail, remediation FROM posture.drift_scan($1)", d.RevertGrace)
	if err != nil {
		return res, fmt.Errorf("drift scan: %w", mapErr(err))
	}
	res.Findings, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Finding, error) {
		var f Finding
		err := r.Scan(&f.CheckID, &f.Severity, &f.Controls, &f.Subject, &f.Detail, &f.Remediation)
		return f, err
	})
	if err != nil {
		return res, fmt.Errorf("drift scan: %w", err)
	}
	hb, err := d.heartbeatFindings(ctx)
	if err != nil {
		return res, err
	}
	res.Findings = append(res.Findings, hb...)
	payload, err := json.Marshal(res.Findings)
	if err != nil {
		return res, err
	}
	if res.Findings == nil {
		payload = []byte("[]")
	}

	err = pgx.BeginFunc(ctx, d.DB, func(tx pgx.Tx) error {
		var err error
		res.Opened, res.Resolved, err = recordFindings(ctx, tx, d.Audit, "app", driftChecks, payload)
		return err
	})
	if err != nil {
		return ScanResult{}, fmt.Errorf("drift findings: %w", mapErr(err))
	}
	return res, nil
}

// recordFindings syncs one scan's findings of the given kind and checks
// (posture.sync_drift_findings) and audits every opened and resolved
// finding inside tx: if an event cannot be written, the caller's
// transaction records nothing (fail closed).
func recordFindings(ctx context.Context, tx pgx.Tx, em audit.Emitter, kind string, checks []string, payload []byte) (opened, resolved []Finding, err error) {
	rows, err := tx.Query(ctx, `SELECT action, finding_id::text, check_id, kind, severity, controls, subject, detail, remediation,
		coalesce(acknowledged_by::text, '') FROM posture.sync_drift_findings($1, $2, $3)`, checks, payload, kind)
	if err != nil {
		return nil, nil, err
	}
	type change struct {
		action string
		f      Finding
	}
	changes, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (change, error) {
		var c change
		err := r.Scan(&c.action, &c.f.ID, &c.f.CheckID, &c.f.Kind, &c.f.Severity, &c.f.Controls, &c.f.Subject, &c.f.Detail,
			&c.f.Remediation, &c.f.AcknowledgedBy)
		return c, err
	})
	if err != nil {
		return nil, nil, err
	}
	for _, c := range changes {
		ev := audit.Event{Type: EventDriftResolved, Severity: audit.SeverityInfo, Actor: DriftActor, Target: c.f.Subject, Attributes: c.f.eventAttrs()}
		if c.action == "opened" {
			ev.Type, ev.Severity = EventDriftDetected, audit.SeverityHigh // AC-37
			if c.f.Severity == "critical" {
				ev.Severity = audit.SeverityCritical
			}
			opened = append(opened, c.f)
		} else {
			resolved = append(resolved, c.f)
		}
		if err := em.Emit(ctx, ev); err != nil {
			return nil, nil, fmt.Errorf("audit: %w", err) // fail closed: nothing is recorded
		}
	}
	return opened, resolved, nil
}

type heartbeat struct {
	service, instance, digest string
	version, current          int64
	values                    map[string]json.RawMessage
	received, changed, now    time.Time
}

// heartbeatFindings is check 4: every service instance heard from recently
// must enforce the current snapshot (same digest), or still report an older
// version only within StaleAfter of the change.
func (d Drift) heartbeatFindings(ctx context.Context) ([]Finding, error) {
	rows, err := d.DB.Query(ctx, `SELECT service, instance, version, digest, "values", received_at, current_version, changed_at, now
		FROM posture.recent_heartbeats($1)`, d.HeartbeatWindow)
	if err != nil {
		return nil, fmt.Errorf("heartbeats: %w", err)
	}
	hbs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (heartbeat, error) {
		var h heartbeat
		err := r.Scan(&h.service, &h.instance, &h.version, &h.digest, &h.values, &h.received, &h.current, &h.changed, &h.now)
		return h, err
	})
	if err != nil || len(hbs) == 0 {
		return nil, err
	}
	snap, err := settings.DBSource{DB: d.DB}.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("heartbeats: snapshot: %w", err)
	}
	if snap.Version != hbs[0].current {
		return nil, nil // posture changed while reading: the next scan compares
	}
	want := snap.Digest()
	var out []Finding
	for _, h := range hbs {
		subject := "service:" + h.service + "/" + h.instance
		detail := map[string]any{"service": h.service, "instance": h.instance, "reported_version": h.version,
			"current_version": snap.Version, "received_at": h.received}
		switch {
		case h.version == snap.Version && h.digest == want:
			continue
		case h.version < snap.Version:
			// Within StaleAfter of the change, every instance should have
			// polled and sent a heartbeat with the new version; one whose
			// latest heartbeat is still older is stale (or has gone quiet).
			if h.now.Sub(h.changed) <= d.StaleAfter {
				continue
			}
			out = append(out, finding(CheckStaleCache, "high", subject, detail,
				"The service is enforcing an older settings snapshot than the one in force. Check its connection to the posture database and NATS; it fails closed once its snapshot is too old."))
		default: // the current version with other values, or a version that does not exist
			detail["differing_keys"] = differingKeys(h.values, snap.Instance)
			detail["reported_digest"], detail["expected_digest"] = h.digest, want
			out = append(out, finding(CheckSettingsMatch, "critical", subject, detail,
				"The service reports settings that differ from the snapshot in force. Restart the instance and investigate how its configuration was changed."))
		}
	}
	return out, nil
}

func finding(check, severity, subject string, detail map[string]any, remediation string) Finding {
	b, _ := json.Marshal(detail)
	return Finding{CheckID: check, Severity: severity, Controls: []string{"CM-6", "SI-7"}, Subject: subject, Detail: b, Remediation: remediation}
}

// differingKeys lists the reported instance values that differ from the
// snapshot (keys a service does not register are not reported).
func differingKeys(reported, want map[string]json.RawMessage) []string {
	keys := []string{}
	for k, v := range reported {
		var a, b bytes.Buffer
		_ = json.Compact(&a, v)
		_ = json.Compact(&b, want[k])
		if !bytes.Equal(a.Bytes(), b.Bytes()) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

// RecordHeartbeat stores a heartbeat received on posture.settings.heartbeat.
func RecordHeartbeat(ctx context.Context, db *pgxpool.Pool, data []byte) error {
	if !json.Valid(data) {
		return fmt.Errorf("%w: heartbeat is not JSON", ErrInvalidValue)
	}
	_, err := db.Exec(ctx, "SELECT posture.record_heartbeat($1)", data)
	return mapErr(err)
}

// OpenFindings returns the drift findings not yet resolved (open or
// acknowledged), most severe first.
func OpenFindings(ctx context.Context, db *pgxpool.Pool) ([]Finding, error) {
	return Findings(ctx, db, time.Time{})
}

// Findings returns the unresolved findings, then those resolved since
// resolvedSince (none when zero), for the Posture page.
func Findings(ctx context.Context, db *pgxpool.Pool, resolvedSince time.Time) ([]Finding, error) {
	var since any
	if !resolvedSince.IsZero() {
		since = resolvedSince
	}
	rows, err := db.Query(ctx, `SELECT finding_id::text, kind, check_id, severity, controls, subject, detail, remediation, status,
		first_seen, last_seen, coalesce(acknowledged_by::text, ''), acknowledged_at, coalesce(acknowledge_reason, ''), resolved_at
		FROM posture.drift_findings($1)`, since)
	if err != nil {
		return nil, mapErr(err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Finding, error) {
		var f Finding
		err := r.Scan(&f.ID, &f.Kind, &f.CheckID, &f.Severity, &f.Controls, &f.Subject, &f.Detail, &f.Remediation, &f.Status,
			&f.FirstSeen, &f.LastSeen, &f.AcknowledgedBy, &f.AcknowledgedAt, &f.AcknowledgeReason, &f.ResolvedAt)
		return f, err
	})
}

// Acknowledge records, as p (who needs drift.acknowledge), that people are
// handling an open finding, with a stated reason; audited inside the
// transaction. It does not close the finding: only its check resolves it.
func (d Drift) Acknowledge(ctx context.Context, p authz.Principal, findingID, reason string) (Finding, error) {
	f := Finding{ID: findingID}
	err := authz.WithDBContext(ctx, d.DB, p.DBToken, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT check_id, kind, severity, controls, subject, remediation, acknowledged_by::text
			FROM posture.acknowledge_drift($1, $2)`, findingID, reason).
			Scan(&f.CheckID, &f.Kind, &f.Severity, &f.Controls, &f.Subject, &f.Remediation, &f.AcknowledgedBy); err != nil {
			return err
		}
		f.Status, f.AcknowledgeReason = "acknowledged", strings.TrimSpace(reason)
		return d.Audit.Emit(ctx, audit.Event{Type: EventDriftAcknowledged, Severity: audit.SeverityLow, Actor: p.UserID,
			Target: f.Subject, Reason: f.AcknowledgeReason, Attributes: f.eventAttrs()})
	})
	if err != nil {
		return Finding{}, mapErr(err)
	}
	return f, nil
}

// RunDrift scans until ctx ends (design §6.7): whenever the posture version
// moves (checked every poll; this includes direct database edits that fire
// the version triggers), whenever wake fires (posture.setting.changed,
// imports, switches), and at least every 15 minutes.
func RunDrift(ctx context.Context, d Drift, poll time.Duration, wake <-chan struct{}, onError func(error)) {
	t := time.NewTicker(poll)
	defer t.Stop()
	src := settings.DBSource{DB: d.DB}
	var scanned int64 = -1
	var last time.Time
	for {
		v, err := src.Version(ctx)
		if err != nil && ctx.Err() == nil {
			onError(err)
		}
		if err == nil && (v != scanned || time.Since(last) >= defaultFullScanEach) {
			if _, err := d.Scan(ctx); err != nil {
				if ctx.Err() == nil {
					onError(err)
				}
			} else {
				scanned, last = v, time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-wake:
			scanned = -1 // scan now, even if the version has not moved
		}
	}
}
