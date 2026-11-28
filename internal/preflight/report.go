package preflight

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/installer"
	"github.com/rformer/fair-app/internal/scanner"
)

// Format is the report format (docs/formats/fair-preflight-report-v1.md).
const Format = "fair.preflight-report.v1"

// Results of a run.
const (
	Passed              = "passed"                // every check passed
	PassedWithOverrides = "passed_with_overrides" // every failed finding overridden
	Refused             = "refused"               // a failed finding not overridden, or a check that could not run
)

// Results of a check.
const (
	ResultPassed        = "passed"
	ResultFailed        = "failed"
	ResultOverridden    = "overridden" // failed, every finding overridden
	ResultError         = "error"      // could not run (never passed)
	ResultNotApplicable = "not_applicable"
)

// Redacted replaces a detail value that looks secret.
const Redacted = "[redacted]"

// Report is a preflight run's report (fair.preflight-report.v1).
type Report struct {
	Format    string           `json:"format"`
	Release   string           `json:"release"`
	Purpose   string           `json:"purpose"`
	Mode      string           `json:"mode"`
	Profile   string           `json:"profile,omitempty"`
	Started   string           `json:"started"`
	Finished  string           `json:"finished"`
	Result    string           `json:"result"`
	Checks    []CheckResult    `json:"checks"`
	Overrides []OverrideResult `json:"overrides"`
}

// CheckResult is one check's outcome.
type CheckResult struct {
	ID           string        `json:"id"`
	Title        string        `json:"title"`
	Source       string        `json:"source"`
	Controls     []string      `json:"controls"`
	Result       string        `json:"result"`
	Error        string        `json:"error,omitempty"`
	Findings     []Finding     `json:"findings"`
	Observations []Observation `json:"observations"`
}

// Finding is one failure of a check.
type Finding struct {
	Subject     string          `json:"subject"`
	Severity    string          `json:"severity"`
	Controls    []string        `json:"controls"`
	Detail      json.RawMessage `json:"detail"` // what was found (a JSON object; values that look secret redacted)
	Remediation string          `json:"remediation"`
	HardFloor   bool            `json:"hard_floor"`
	Overridden  bool            `json:"overridden"`
}

// Observation records how a passing subject was assessed ("verified" or
// "attested").
type Observation struct {
	Subject string          `json:"subject"`
	Method  string          `json:"method"`
	Detail  json.RawMessage `json:"detail"`
}

// OverrideResult is an override and whether it applied.
type OverrideResult struct {
	Override
	Applied bool   `json:"applied"`
	Refusal string `json:"refusal,omitempty"` // why it did not apply
}

// fill records a check's outcome.
func (r *CheckResult) fill(c Check, res scanner.Result, err error, ctx Context) {
	r.Findings, r.Observations = []Finding{}, []Observation{}
	if err != nil {
		r.Result, r.Error = ResultError, redactText(err.Error())
		return
	}
	for _, f := range res.Findings {
		fd := Finding{Subject: redactText(f.Subject), Severity: f.Severity, Controls: slices.Clone(f.Controls),
			Detail: redactJSON(f.DetailJSON), Remediation: redactText(f.Remediation)}
		if fd.Controls == nil {
			fd.Controls = []string{}
		}
		fd.HardFloor = c.floor != nil && c.floor(fd, ctx)
		r.Findings = append(r.Findings, fd)
	}
	for _, ob := range res.Observations {
		r.Observations = append(r.Observations, Observation{Subject: redactText(ob.Subject), Method: ob.Method, Detail: redactJSON(ob.DetailJSON)})
	}
	sort.SliceStable(r.Findings, func(i, j int) bool { return r.Findings[i].Subject < r.Findings[j].Subject })
	sort.SliceStable(r.Observations, func(i, j int) bool { return r.Observations[i].Subject < r.Observations[j].Subject })
	r.Result = ResultPassed
	if len(r.Findings) > 0 {
		r.Result = ResultFailed
	}
}

// applyOverrides applies the overrides and sets the result. An override
// applies to the failed findings of its check and subject that are not on
// the hard floor, never in SaaS (OQ4).
func (r *Report) applyOverrides(ovs []Override) {
	r.Overrides = []OverrideResult{}
	for _, o := range ovs {
		or := OverrideResult{Override: Override{Check: o.Check, Subject: redactText(o.Subject), Reason: redactText(o.Reason)}}
		matched, floor := false, false
		for i := range r.Checks {
			c := &r.Checks[i]
			if c.ID != o.Check {
				continue
			}
			for j := range c.Findings {
				f := &c.Findings[j]
				if f.Subject != o.Subject {
					continue
				}
				matched = true
				if f.HardFloor {
					floor = true
					continue
				}
				if r.Mode != ModeSaaS {
					f.Overridden = true
					or.Applied = true
				}
			}
		}
		switch {
		case !matched:
			or.Refusal = "matches no failed finding"
		case r.Mode == ModeSaaS:
			or.Refusal = "SaaS allows no override"
		case floor && !or.Applied:
			or.Refusal = "on the hard floor: no override"
		}
		r.Overrides = append(r.Overrides, or)
	}
	r.Result = Passed
	for i := range r.Checks {
		c := &r.Checks[i]
		switch c.Result {
		case ResultError:
			r.Result = Refused
			continue
		case ResultFailed:
		default:
			continue
		}
		all := true
		for _, f := range c.Findings {
			all = all && f.Overridden
		}
		if !all {
			r.Result = Refused
			continue
		}
		c.Result = ResultOverridden
		if r.Result == Passed {
			r.Result = PassedWithOverrides
		}
	}
}

// Failures are the findings not overridden and the checks that could not
// run, as "check subject" pairs (subject "" for an error).
func (r *Report) Failures() [][2]string {
	var out [][2]string
	for _, c := range r.Checks {
		if c.Result == ResultError {
			out = append(out, [2]string{c.ID, ""})
		}
		for _, f := range c.Findings {
			if !f.Overridden {
				out = append(out, [2]string{c.ID, f.Subject})
			}
		}
	}
	return out
}

// Encode returns the report's stored form: compact JSON (struct field
// order, object keys of details sorted).
func (r *Report) Encode() ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Record is a run as install.record_preflight stores it (design §5).
type Record struct {
	RunID    string          `json:"run_id"`
	Release  string          `json:"release"`
	Purpose  string          `json:"purpose"`
	Started  time.Time       `json:"started"`
	Finished time.Time       `json:"finished"`
	Result   string          `json:"result"`
	Report   json.RawMessage `json:"report"`
	Digest   string          `json:"digest"` // SHA-256 of Report, hex
}

// ErrSecret refuses a report holding a value that looks secret.
var ErrSecret = errors.New("preflight: the report holds a value that looks secret")

// Record returns the run's record under a run identifier (NewRunID). It
// refuses a report any of whose strings looks secret (the findings'
// details are redacted when built; this is the last guard before the
// report is stored or printed).
func (r *Report) Record(runID string) (*Record, error) {
	b, err := r.Encode()
	if err != nil {
		return nil, err
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if secretIn(v) {
		return nil, ErrSecret
	}
	started, err := time.Parse(time.RFC3339Nano, r.Started)
	if err != nil {
		return nil, fmt.Errorf("preflight: started: %w", err)
	}
	finished, err := time.Parse(time.RFC3339Nano, r.Finished)
	if err != nil {
		return nil, fmt.Errorf("preflight: finished: %w", err)
	}
	sum := sha256.Sum256(b)
	return &Record{RunID: runID, Release: r.Release, Purpose: r.Purpose, Started: started, Finished: finished, Result: r.Result,
		Report: b, Digest: hex.EncodeToString(sum[:])}, nil
}

// NewRunID returns a random (version 4) UUID.
func NewRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// redactText returns s, or Redacted when it looks secret.
func redactText(s string) string {
	if installer.LooksSecret(s) {
		return Redacted
	}
	return s
}

// redactJSON returns a finding's detail object with every string that
// looks secret redacted, its keys sorted; not an object: {}.
func redactJSON(s string) json.RawMessage {
	var v any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return json.RawMessage(`{}`)
	}
	if _, ok := v.(map[string]any); !ok {
		return json.RawMessage(`{}`)
	}
	b, err := json.Marshal(redact(v))
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

func redact(v any) any {
	switch x := v.(type) {
	case string:
		return redactText(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			if installer.LooksSecret(k) {
				k = Redacted
			}
			out[k] = redact(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = redact(e)
		}
		return out
	default:
		return v
	}
}

func secretIn(v any) bool {
	switch x := v.(type) {
	case string:
		return installer.LooksSecret(x)
	case map[string]any:
		for k, e := range x {
			if installer.LooksSecret(k) || secretIn(e) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if secretIn(e) {
				return true
			}
		}
	}
	return false
}
