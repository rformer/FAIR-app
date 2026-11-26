// Package changeevidence assembles the change evidence of F-012-AC-26
// (F-012 T-17, design §3.8, §6 "T, R: unreviewed or unattributed production
// changes"): for a period, and optionally one instance, the chain pull
// request -> approver (never the author) -> required check runs -> release
// (its signatures and the release pipeline's signing, provenance and
// verification jobs) -> deployment to each instance (Flux's events, kept by
// the operations account) and infrastructure applies (the protected
// environment "instances" of infra-instances.yml, with its approvals).
//
// Everything is read from the GitHub REST API (GitHub, read-only, a token
// from a file) and from Flux's recorded events; nothing is changed. The
// report (format fair.change-evidence.v1, docs/formats/
// fair-change-evidence-v1.md) is deterministic for the same inputs, and
// every gap in the chain is a Finding: a gap never fails the export, it is
// what the export is for.
package changeevidence

import (
	"bytes"
	"encoding/csv"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/profilepkg"
)

// Format identifies the report format.
const Format = "fair.change-evidence.v1"

// Report is the change evidence of one period.
type Report struct {
	Format          string   `json:"format"`
	Repository      string   `json:"repository"`
	FleetRepository string   `json:"fleet_repository,omitempty"`
	From            string   `json:"from"` // inclusive, RFC 3339 UTC
	To              string   `json:"to"`   // exclusive
	Instance        string   `json:"instance,omitempty"`
	RequiredChecks  []string `json:"required_checks"`
	ReleaseJobs     []string `json:"release_jobs"`

	PullRequests []PullRequest `json:"pull_requests"`
	Releases     []Release     `json:"releases"`
	Deployments  []Deployment  `json:"deployments"`
	Applies      []Apply       `json:"infrastructure_applies"`
	Findings     []Finding     `json:"findings"`
}

// PullRequest is one merged pull request.
type PullRequest struct {
	ID          string   `json:"id"` // owner/name#number
	Repository  string   `json:"repository"`
	Number      int      `json:"number"`
	Title       string   `json:"title"`
	URL         string   `json:"url"`
	Author      string   `json:"author"`
	MergedAt    string   `json:"merged_at"`
	MergeCommit string   `json:"merge_commit"`
	Head        string   `json:"head"`
	Approvers   []string `json:"approvers"` // approved the merged head; neither the author nor a commit author
	Reviews     []Review `json:"reviews"`
	// Checks are the required checks on the merged head (the main
	// repository's pull requests; the fleet repository has none listed).
	Checks []Check `json:"checks"`
}

// Review is one submitted review.
type Review struct {
	User        string `json:"user"`
	State       string `json:"state"`
	Commit      string `json:"commit"`
	SubmittedAt string `json:"submitted_at,omitempty"`
}

// Check is one required check's run on the pull request's head.
type Check struct {
	Name       string `json:"name"`
	Conclusion string `json:"conclusion"` // GitHub's conclusion, the status while not completed, or "missing"
	URL        string `json:"url,omitempty"`
}

// Release is one release and its signing evidence.
type Release struct {
	Tag         string `json:"tag"`
	URL         string `json:"url,omitempty"`
	PublishedAt string `json:"published_at,omitempty"`
	Prerelease  bool   `json:"prerelease"`
	Commit      string `json:"commit,omitempty"`
	Previous    string `json:"previous,omitempty"` // the base its commits are counted from
	// Manifest is the SHA-256 of release-manifest.json; ManifestSignature
	// and SumsSignature are "verified", "missing" or "invalid" under the
	// release key; ReleaseKey says whether the release's cosign.pub is that
	// key ("matches", "missing", "differs").
	Manifest          string            `json:"manifest,omitempty"`
	ManifestSignature string            `json:"manifest_signature"`
	SumsSignature     string            `json:"sums_signature"`
	ReleaseKey        string            `json:"release_key"`
	Images            map[string]string `json:"images"`
	// Run is the release workflow's run for the tag: its signing
	// (keyless and release key), SLSA provenance and verification jobs
	// (scripts/verify-release.sh, online and offline) are the attestations'
	// evidence.
	Run          *Run     `json:"run,omitempty"`
	Commits      int      `json:"commits"`
	PullRequests []string `json:"pull_requests"`
}

// Run is a workflow run.
type Run struct {
	ID         int64  `json:"id"`
	URL        string `json:"url"`
	Commit     string `json:"commit"`
	Conclusion string `json:"conclusion"`
	Jobs       []Job  `json:"jobs"`
}

// Job is one job of a run.
type Job struct {
	Name       string `json:"name"`
	Conclusion string `json:"conclusion"`
}

// Deployment is one release rolled out to one instance (Flux's events).
type Deployment struct {
	ID       string `json:"id"` // instance:release
	Instance string `json:"instance"`
	Release  string `json:"release"`
	Artifact string `json:"artifact,omitempty"` // the fleet artifact's digest Flux applied
	// Status: "succeeded" (fair-platform reconciled the release),
	// "failed" (only errors), "incomplete" (no outcome by the period's end).
	Status      string `json:"status"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at,omitempty"`
	Errors      int    `json:"errors"`
	// FleetCommit is the fleet repository's commit applied when the
	// rollout started; FleetPullRequest the pull request that merged it.
	FleetCommit      string `json:"fleet_commit,omitempty"`
	FleetPullRequest string `json:"fleet_pull_request,omitempty"`
}

// Apply is one instance's infrastructure apply (infra-instances.yml).
type Apply struct {
	ID          string     `json:"id"` // instance:run
	Instance    string     `json:"instance"`
	Run         int64      `json:"run"`
	URL         string     `json:"url"`
	Commit      string     `json:"commit"`
	CreatedAt   string     `json:"created_at"`
	TriggeredBy string     `json:"triggered_by"`
	Conclusion  string     `json:"conclusion"`
	PullRequest string     `json:"pull_request,omitempty"`
	Approvals   []Approval `json:"approvals"`
}

// Approval is a review of a deployment to a protected environment.
type Approval struct {
	User    string `json:"user"`
	State   string `json:"state"`
	Comment string `json:"comment,omitempty"`
}

// Finding is one gap in the evidence.
type Finding struct {
	Code     string `json:"code"`
	Subject  string `json:"subject"`
	Instance string `json:"instance,omitempty"`
	Release  string `json:"release,omitempty"`
	Detail   string `json:"detail"`
}

// Finding codes (docs/formats/fair-change-evidence-v1.md).
const (
	NoApproval              = "no_approval"
	SelfApproval            = "self_approval"
	StaleApproval           = "stale_approval"
	CheckMissing            = "check_missing"
	CheckFailed             = "check_failed"
	CommitWithoutPR         = "commit_without_pull_request"
	ReleaseNotFound         = "release_not_found"
	ReleaseBaseUnknown      = "release_base_unknown"
	ReleaseUnsigned         = "release_unsigned"
	ReleaseSignatureInvalid = "release_signature_invalid"
	ReleaseManifestMismatch = "release_manifest_mismatch"
	ReleaseSumsUnsigned     = "release_sums_unsigned"
	ReleaseSumsInvalid      = "release_sums_invalid"
	ReleaseKeyMismatch      = "release_key_mismatch"
	ReleaseRunMissing       = "release_run_missing"
	ReleaseJobMissing       = "release_job_missing"
	ReleaseJobFailed        = "release_job_failed"
	ReleaseSourceRefused    = "release_source_refused"
	DeploymentFailed        = "deployment_failed"
	DeploymentIncomplete    = "deployment_incomplete"
	DeploymentUnknown       = "deployment_unknown_release"
	DeploymentUnsigned      = "deployment_unsigned_release"
	DeploymentNoFleetCommit = "deployment_without_fleet_commit"
	DeploymentNoPR          = "deployment_without_pull_request"
	DeploymentUnapproved    = "deployment_unapproved"
	FleetNotChecked         = "fleet_change_not_checked"
	ApplyUnapproved         = "apply_unapproved"
	ApplySelfApproved       = "apply_self_approved"
	ApplyFailed             = "apply_failed"
	ApplyNotCompleted       = "apply_not_completed"
	ApplyNoPR               = "apply_without_pull_request"
)

// Codes is every finding code.
var Codes = []string{
	NoApproval, SelfApproval, StaleApproval, CheckMissing, CheckFailed, CommitWithoutPR,
	ReleaseNotFound, ReleaseBaseUnknown, ReleaseUnsigned, ReleaseSignatureInvalid, ReleaseManifestMismatch,
	ReleaseSumsUnsigned, ReleaseSumsInvalid, ReleaseKeyMismatch, ReleaseRunMissing, ReleaseJobMissing,
	ReleaseJobFailed, ReleaseSourceRefused, DeploymentFailed, DeploymentIncomplete, DeploymentUnknown,
	DeploymentUnsigned, DeploymentNoFleetCommit, DeploymentNoPR, DeploymentUnapproved, FleetNotChecked,
	ApplyUnapproved, ApplySelfApproved, ApplyFailed, ApplyNotCompleted, ApplyNoPR,
}

// JSON is the report's canonical bytes (what is signed).
func (r *Report) JSON() ([]byte, error) {
	r.normalize()
	return profilepkg.Encode(r)
}

// CSV is the report as one table: a row per pull request, release,
// deployment and apply, with the codes of the findings about it, then a
// row per finding.
func (r *Report) CSV() ([]byte, error) {
	r.normalize()
	about := map[string][]string{}
	for _, f := range r.Findings {
		about[f.Subject] = append(about[f.Subject], f.Code)
	}
	codes := func(subject string) string {
		c := slices.Clone(about[subject])
		slices.Sort(c)
		return strings.Join(slices.Compact(c), ";")
	}
	rows := [][]string{{"record", "id", "instance", "time", "actor", "approvers", "release", "status", "url", "findings"}}
	for _, p := range r.PullRequests {
		status := "approved"
		if len(p.Approvers) == 0 {
			status = "unapproved"
		}
		rows = append(rows, []string{"pull_request", p.ID, "", p.MergedAt, p.Author, strings.Join(p.Approvers, ";"), "", status, p.URL, codes(Subject("pull_request", p.ID))})
	}
	for _, x := range r.Releases {
		rows = append(rows, []string{"release", x.Tag, "", x.PublishedAt, "", "", x.Tag, x.ManifestSignature, x.URL, codes(Subject("release", x.Tag))})
	}
	for _, d := range r.Deployments {
		t := d.CompletedAt
		if t == "" {
			t = d.StartedAt
		}
		rows = append(rows, []string{"deployment", d.ID, d.Instance, t, "", "", d.Release, d.Status, "", codes(Subject("deployment", d.ID))})
	}
	for _, a := range r.Applies {
		var who []string
		for _, x := range a.Approvals {
			who = append(who, x.User+":"+x.State)
		}
		rows = append(rows, []string{"apply", a.ID, a.Instance, a.CreatedAt, a.TriggeredBy, strings.Join(who, ";"), "", a.Conclusion, a.URL, codes(Subject("apply", a.ID))})
	}
	for _, f := range r.Findings {
		rows = append(rows, []string{"finding", f.Subject, f.Instance, "", "", "", f.Release, f.Code, "", f.Detail})
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	for _, row := range rows {
		for i := range row {
			row[i] = neutralize(row[i])
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// neutralize keeps a spreadsheet from reading a cell as a formula.
func neutralize(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// Subject names the item a finding is about.
func Subject(kind, id string) string { return kind + ":" + id }

// FindingCodes are the findings' codes, sorted and unique.
func (r *Report) FindingCodes() []string {
	var c []string
	for _, f := range r.Findings {
		c = append(c, f.Code)
	}
	slices.Sort(c)
	return slices.Compact(c)
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// normalize sorts everything and replaces nil lists with empty ones, so
// the same evidence always encodes to the same bytes.
func (r *Report) normalize() {
	r.Format = Format
	r.RequiredChecks = sorted(r.RequiredChecks)
	r.ReleaseJobs = sorted(r.ReleaseJobs)
	if r.PullRequests == nil {
		r.PullRequests = []PullRequest{}
	}
	for i := range r.PullRequests {
		p := &r.PullRequests[i]
		p.Approvers = sorted(p.Approvers)
		if p.Reviews == nil {
			p.Reviews = []Review{}
		}
		sort.SliceStable(p.Reviews, func(a, b int) bool {
			x, y := p.Reviews[a], p.Reviews[b]
			if x.SubmittedAt != y.SubmittedAt {
				return x.SubmittedAt < y.SubmittedAt
			}
			return x.User < y.User
		})
		if p.Checks == nil {
			p.Checks = []Check{}
		}
		sort.Slice(p.Checks, func(a, b int) bool { return p.Checks[a].Name < p.Checks[b].Name })
	}
	sort.Slice(r.PullRequests, func(a, b int) bool {
		x, y := r.PullRequests[a], r.PullRequests[b]
		if x.Repository != y.Repository {
			return x.Repository < y.Repository
		}
		return x.Number < y.Number
	})
	if r.Releases == nil {
		r.Releases = []Release{}
	}
	for i := range r.Releases {
		x := &r.Releases[i]
		x.PullRequests = sorted(x.PullRequests)
		if x.Images == nil {
			x.Images = map[string]string{}
		}
		if x.Run != nil {
			if x.Run.Jobs == nil {
				x.Run.Jobs = []Job{}
			}
			sort.Slice(x.Run.Jobs, func(a, b int) bool { return x.Run.Jobs[a].Name < x.Run.Jobs[b].Name })
		}
	}
	sort.Slice(r.Releases, func(a, b int) bool { return r.Releases[a].Tag < r.Releases[b].Tag })
	if r.Deployments == nil {
		r.Deployments = []Deployment{}
	}
	sort.Slice(r.Deployments, func(a, b int) bool {
		x, y := r.Deployments[a], r.Deployments[b]
		if x.Instance != y.Instance {
			return x.Instance < y.Instance
		}
		if x.StartedAt != y.StartedAt {
			return x.StartedAt < y.StartedAt
		}
		return x.Release < y.Release
	})
	if r.Applies == nil {
		r.Applies = []Apply{}
	}
	for i := range r.Applies {
		a := &r.Applies[i]
		if a.Approvals == nil {
			a.Approvals = []Approval{}
		}
		sort.Slice(a.Approvals, func(x, y int) bool {
			if a.Approvals[x].User != a.Approvals[y].User {
				return a.Approvals[x].User < a.Approvals[y].User
			}
			return a.Approvals[x].State < a.Approvals[y].State
		})
	}
	sort.Slice(r.Applies, func(a, b int) bool {
		x, y := r.Applies[a], r.Applies[b]
		if x.Instance != y.Instance {
			return x.Instance < y.Instance
		}
		return x.Run < y.Run
	})
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	sort.Slice(r.Findings, func(a, b int) bool {
		x, y := r.Findings[a], r.Findings[b]
		for _, c := range [][2]string{{x.Subject, y.Subject}, {x.Code, y.Code}, {x.Instance, y.Instance}, {x.Release, y.Release}, {x.Detail, y.Detail}} {
			if c[0] != c[1] {
				return c[0] < c[1]
			}
		}
		return false
	})
	r.Findings = slices.Compact(r.Findings)
}

func sorted(s []string) []string {
	out := slices.Clone(s)
	if out == nil {
		return []string{}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
