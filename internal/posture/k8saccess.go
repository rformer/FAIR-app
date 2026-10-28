package posture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/checks"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// Kubernetes-access consent (F-015 T-30; AC-39, AC-40; design §6.8;
// migration 0032). The installer records the customer's decision against
// the permission manifest's digest; a later grant waits for an admin's
// acknowledgement. While access is not granted, scanner reports are refused,
// the Posture page shows a persistent warning, and every deployment check is
// "Not assessed".

// Kubernetes access states.
const (
	AccessUndecided = "undecided"
	AccessRequested = "requested"
	AccessGranted   = "granted"
	AccessDeclined  = "declined"
	AccessRevoked   = "revoked"
)

// InstallerActor is the audit actor of installer decisions.
const InstallerActor = "system:installer"

// K8sAccess manages the consent.
type K8sAccess struct {
	DB    *pgxpool.Pool // app_posture
	Audit audit.Emitter
}

// AccessStatus is the consent state as the Posture page shows it.
type AccessStatus struct {
	State          string
	Digest         string // the permission manifest consented to (or requested)
	CurrentDigest  string // this release's permission manifest
	DecidedActor   string
	DecidedAt      *time.Time
	Reason         string
	DeploymentMode string
	LastReport     *time.Time
	// Warning is the persistent banner (AC-40); "" when none is needed.
	Warning string
}

func currentDigest() (string, error) {
	m, err := scanner.Manifest()
	if err != nil {
		return "", err
	}
	return m.Digest()
}

// Decide records an installer decision (granted, declined, requested or
// revoked) for this release's permission manifest; declining and revoking
// need a reason. Audited inside the transaction (declines and revocations
// high). Returns the previous state.
func (k K8sAccess) Decide(ctx context.Context, state, reason, actor string) (string, error) {
	digest, err := currentDigest()
	if err != nil {
		return "", err
	}
	if actor == "" {
		actor = InstallerActor
	}
	var prev string
	err = pgx.BeginFunc(ctx, k.DB, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT posture.decide_k8s_access($1, $2, $3, $4)", state, nullable(reason), digest, actor).Scan(&prev); err != nil {
			return err
		}
		sev := audit.SeverityInfo
		switch state {
		case AccessDeclined, AccessRevoked:
			sev = audit.SeverityHigh
		case AccessRequested:
			sev = audit.SeverityLow
		}
		return k.Audit.Emit(ctx, audit.Event{Type: "posture.k8s_access_" + state, Severity: sev, Actor: actor, Target: "posture:k8s-access",
			Reason: reason, Attributes: map[string]string{"previous": prev, "state": state, "permissions_digest": digest}})
	})
	return prev, mapErr(err)
}

// Acknowledge grants requested access as p (settings.change at the root)
// for the permission manifest digest p was shown.
func (k K8sAccess) Acknowledge(ctx context.Context, p authz.Principal, digest string) error {
	return mapErr(authz.WithDBContext(ctx, k.DB, p.DBToken, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT posture.acknowledge_k8s_access($1)", digest); err != nil {
			return err
		}
		return k.Audit.Emit(ctx, audit.Event{Type: "posture.k8s_access_granted", Severity: audit.SeverityInfo, Actor: p.UserID,
			Target: "posture:k8s-access", Attributes: map[string]string{"previous": AccessRequested, "state": AccessGranted,
				"permissions_digest": digest, "acknowledged": "true"}})
	}))
}

// Status returns the consent state and the banner to show.
func (k K8sAccess) Status(ctx context.Context) (AccessStatus, error) { return accessStatus(ctx, k.DB) }

func accessStatus(ctx context.Context, db Reader) (AccessStatus, error) {
	var s AccessStatus
	var digest, actor, reason, mode *string // mode is unset until the installer records it (T-15)
	if err := db.QueryRow(ctx, `SELECT state, permissions_digest, decided_actor, decided_at, reason, deployment_mode, last_report
		FROM posture.k8s_access_status()`).Scan(&s.State, &digest, &actor, &s.DecidedAt, &reason, &mode, &s.LastReport); err != nil {
		return s, mapErr(err)
	}
	s.Digest, s.DecidedActor, s.Reason, s.DeploymentMode = deref(digest), deref(actor), deref(reason), deref(mode)
	var err error
	if s.CurrentDigest, err = currentDigest(); err != nil {
		return s, err
	}
	const disabled = " Deployment drift detection is disabled and deployment controls are reported as Not assessed."
	when := ""
	if s.DecidedAt != nil {
		when = " on " + s.DecidedAt.UTC().Format("2006-01-02")
	}
	switch s.State {
	case AccessUndecided:
		s.Warning = "Kubernetes access for deployment drift detection has not been decided." + disabled
	case AccessDeclined:
		s.Warning = "Kubernetes access was declined" + when + "." + disabled +
			" To grant it later, enable the scanner in the installer and acknowledge the request here."
	case AccessRevoked:
		s.Warning = "Kubernetes access was revoked" + when + "." + disabled
	case AccessRequested:
		s.Warning = "The scanner was enabled in the installer and awaits an administrator's acknowledgement of its permissions." + disabled
	case AccessGranted:
		if s.Digest != "" && s.Digest != s.CurrentDigest {
			s.Warning = "This release changes the scanner's permissions; review them and re-confirm access in the installer."
		}
	}
	return s, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ErrAccessNotGranted is why scanner reports are refused without consent.
var ErrAccessNotGranted = errors.New("posture: Kubernetes access is not granted; deployment drift detection is disabled")

func (k K8sAccess) requireGranted(ctx context.Context) error {
	var state string
	if err := k.DB.QueryRow(ctx, "SELECT state FROM posture.k8s_access_status()").Scan(&state); err != nil {
		return err
	}
	if state != AccessGranted {
		return fmt.Errorf("%w (%s)", ErrAccessNotGranted, state)
	}
	return nil
}

// CheckAssessment is whether a deployment check currently assesses its
// controls (the OSCAL export's "Not assessed", T-33).
type CheckAssessment struct {
	CheckID  string
	Title    string
	Controls []string
	Assessed bool
	Reason   string // why not assessed
}

// Assessment maps every deployment check to assessed or Not assessed:
// Not assessed while access is not granted (AC-40), when the scanner has not
// reported within staleAfter (default 45 minutes, three scan intervals), or
// when the check did not complete in the latest report.
func (k K8sAccess) Assessment(ctx context.Context, staleAfter time.Duration) ([]CheckAssessment, error) {
	as, _, err := assessment(ctx, k.DB, time.Now(), staleAfter)
	return as, err
}

// assessment is Assessment as of now, read through db (a transaction, for
// the export's consistent snapshot); it also returns the latest scanner
// report's time (zero when there is none).
func assessment(ctx context.Context, db Reader, now time.Time, staleAfter time.Duration) ([]CheckAssessment, time.Time, error) {
	if staleAfter <= 0 {
		staleAfter = 45 * time.Minute
	}
	st, err := accessStatus(ctx, db)
	if err != nil {
		return nil, time.Time{}, err
	}
	var latest struct {
		received time.Time
		run      []string
		errors   map[string]string
	}
	if st.State == AccessGranted {
		var errs json.RawMessage
		err := db.QueryRow(ctx, "SELECT received_at, checks_run, check_errors FROM posture.scanner_reports() LIMIT 1").
			Scan(&latest.received, &latest.run, &errs)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, time.Time{}, mapErr(err)
		}
		var list []map[string]string
		_ = json.Unmarshal(errs, &list)
		latest.errors = map[string]string{}
		for _, e := range list {
			latest.errors[e["check_id"]] = e["error"]
		}
	}
	var out []CheckAssessment
	for _, m := range checks.Metas() {
		a := CheckAssessment{CheckID: m.ID, Title: m.Title, Controls: m.Controls}
		switch {
		case st.State != AccessGranted:
			a.Reason = "Kubernetes access " + st.State
		case latest.received.IsZero():
			a.Reason = "the scanner has not reported"
		case now.Sub(latest.received) > staleAfter:
			a.Reason = "the scanner has not reported since " + latest.received.UTC().Format(time.RFC3339)
		case latest.errors[m.ID] != "":
			a.Reason = "the check failed: " + latest.errors[m.ID]
		case !slices.Contains(latest.run, m.ID):
			a.Reason = "the check did not run"
		default:
			a.Assessed = true
		}
		out = append(out, a)
	}
	return out, latest.received, nil
}

// notGrantedMessage is what a refused scanner is told.
func notGrantedMessage(err error) string {
	return strings.TrimPrefix(err.Error(), "posture: ")
}
