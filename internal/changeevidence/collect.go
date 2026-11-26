package changeevidence

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releasemanifest"
)

// Options say what to collect.
type Options struct {
	Repository      string // owner/name: the platform repository
	FleetRepository string // owner/name, or "": the fleet repository (design §3.6)
	Branch          string // default "main"
	From, To        time.Time
	Instance        string   // "": every instance
	Releases        []string // releases to include besides those published or deployed in the period
	FirstBase       string   // the commit the first release's changes are counted from ("": a finding)
	RequiredChecks  []string // the main repository's required checks (infra/github/variables.tf)
	// ReleaseJobs are the release workflow's jobs that must have succeeded
	// (a matrix "name (x)" or reusable "name / x" job counts as name).
	ReleaseJobs     []string
	ReleaseWorkflow string // default "release.yml"
	InfraWorkflow   string // default "infra-instances.yml"
	Environment     string // default "instances"
	ApplyJob        string // default "apply"
	ReleaseKey      *ecdsa.PublicKey
	FluxEvents      []FluxEvent
}

// DefaultReleaseJobs are the release jobs that must succeed: keyless
// signature and SBOM attestation (build), SLSA provenance, the release
// key's signatures and attestations (sign), publishing, and
// scripts/verify-release.sh online and offline (verify).
var DefaultReleaseJobs = []string{"build", "provenance", "sign", "publish", "verify"}

func (o *Options) defaults() error {
	if o.Branch == "" {
		o.Branch = "main"
	}
	if o.ReleaseWorkflow == "" {
		o.ReleaseWorkflow = "release.yml"
	}
	if o.InfraWorkflow == "" {
		o.InfraWorkflow = "infra-instances.yml"
	}
	if o.Environment == "" {
		o.Environment = "instances"
	}
	if o.ApplyJob == "" {
		o.ApplyJob = "apply"
	}
	if o.ReleaseJobs == nil {
		o.ReleaseJobs = DefaultReleaseJobs
	}
	for _, r := range []string{o.Repository, o.FleetRepository} {
		if r != "" && !repoRE.MatchString(r) {
			return fmt.Errorf("changeevidence: repository %q is not owner/name", r)
		}
	}
	switch {
	case o.Repository == "":
		return errors.New("changeevidence: the repository is required")
	case o.ReleaseKey == nil:
		return errors.New("changeevidence: the release public key is required")
	case o.From.IsZero() || !o.To.After(o.From):
		return errors.New("changeevidence: the period must end after it starts")
	}
	return nil
}

var (
	repoRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

type collector struct {
	gh    *GitHub
	o     Options
	pulls map[string]*PullRequest // by ID
	bySHA map[string]string       // repository@merge commit -> ID
	finds []Finding
}

func (c *collector) find(f Finding) { c.finds = append(c.finds, f) }

// Collect gathers the evidence for o.
func Collect(ctx context.Context, gh *GitHub, o Options) (*Report, error) {
	if err := o.defaults(); err != nil {
		return nil, err
	}
	c := &collector{gh: gh, o: o, pulls: map[string]*PullRequest{}, bySHA: map[string]string{}}
	r := &Report{
		Repository: o.Repository, FleetRepository: o.FleetRepository, Instance: o.Instance,
		From: ts(o.From), To: ts(o.To), RequiredChecks: o.RequiredChecks, ReleaseJobs: o.ReleaseJobs,
	}
	for _, repo := range []string{o.Repository, o.FleetRepository} {
		if repo != "" {
			if err := c.mergedPulls(ctx, repo); err != nil {
				return nil, err
			}
		}
	}
	ds, fs := deployments(o.FluxEvents, o.From, o.To)
	c.finds = append(c.finds, fs...)
	rels, err := c.releases(ctx, ds)
	if err != nil {
		return nil, err
	}
	if err := c.pairDeployments(ctx, ds, rels); err != nil {
		return nil, err
	}
	applies, err := c.applies(ctx)
	if err != nil {
		return nil, err
	}
	r.Deployments = ds
	r.Applies = applies
	for _, x := range rels {
		r.Releases = append(r.Releases, *x)
	}
	for _, p := range c.pulls {
		r.PullRequests = append(r.PullRequests, *p)
	}
	r.Findings = c.finds
	if o.Instance != "" {
		r.only(o.Instance)
	}
	r.normalize()
	return r, nil
}

var errStop = errors.New("stop")

// mergedPulls records every pull request merged into the branch in the
// period. The list is newest-updated first; one updated before the period
// cannot have been merged in it, which ends the walk.
func (c *collector) mergedPulls(ctx context.Context, repo string) error {
	q := url.Values{"state": {"closed"}, "base": {c.o.Branch}, "sort": {"updated"}, "direction": {"desc"}}
	err := c.gh.list(ctx, "/repos/"+repo+"/pulls", q, "", func(raw json.RawMessage) error {
		var p ghPull
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		if p.UpdatedAt.Before(c.o.From) {
			return errStop
		}
		if p.MergedAt == nil || p.MergedAt.Before(c.o.From) || !p.MergedAt.Before(c.o.To) {
			return nil
		}
		_, err := c.addPull(ctx, repo, p)
		return err
	})
	if errors.Is(err, errStop) {
		return nil
	}
	return err
}

// pullFor is the merged pull request that brought commit sha to the
// branch, or nil.
func (c *collector) pullFor(ctx context.Context, repo, sha string) (*PullRequest, error) {
	if id, ok := c.bySHA[repo+"@"+sha]; ok {
		return c.pulls[id], nil
	}
	var found *PullRequest
	err := c.gh.list(ctx, "/repos/"+repo+"/commits/"+sha+"/pulls", nil, "", func(raw json.RawMessage) error {
		var p ghPull
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		if found != nil || p.MergedAt == nil || p.Base.Ref != c.o.Branch {
			return nil
		}
		pr, err := c.addPull(ctx, repo, p)
		found = pr
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if found != nil {
		c.bySHA[repo+"@"+sha] = found.ID
	}
	return found, err
}

// addPull records a merged pull request with its reviews, commits and
// (for the main repository) required checks, and its findings.
func (c *collector) addPull(ctx context.Context, repo string, p ghPull) (*PullRequest, error) {
	id := fmt.Sprintf("%s#%d", repo, p.Number)
	if pr, ok := c.pulls[id]; ok {
		return pr, nil
	}
	pr := &PullRequest{
		ID: id, Repository: repo, Number: p.Number, Title: p.Title, URL: p.HTMLURL, Author: login(p.User),
		MergeCommit: p.MergeCommitSHA, Head: p.Head.SHA,
	}
	if p.MergedAt != nil {
		pr.MergedAt = ts(*p.MergedAt)
	}
	base := fmt.Sprintf("/repos/%s/pulls/%d", repo, p.Number)
	var reviews []ghReview
	if err := c.gh.list(ctx, base+"/reviews", nil, "", func(raw json.RawMessage) error {
		var r ghReview
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		reviews = append(reviews, r)
		return nil
	}); err != nil {
		return nil, err
	}
	authors := map[string]bool{pr.Author: true}
	if err := c.gh.list(ctx, base+"/commits", nil, "", func(raw json.RawMessage) error {
		var cm ghCommit
		if err := json.Unmarshal(raw, &cm); err != nil {
			return err
		}
		if a := login(cm.Author); a != "" {
			authors[a] = true
		}
		return nil
	}); err != nil {
		return nil, err
	}
	subject := Subject("pull_request", id)
	pr.Approvers = c.approvers(pr, reviews, authors, subject)
	if repo == c.o.Repository {
		checks, err := c.checks(ctx, repo, pr.Head, subject)
		if err != nil {
			return nil, err
		}
		pr.Checks = checks
	}
	c.pulls[id] = pr
	if pr.MergeCommit != "" {
		c.bySHA[repo+"@"+pr.MergeCommit] = id
	}
	return pr, nil
}

// approvers are the reviewers whose latest review approved the merged
// head and who are neither the author nor an author of its commits.
func (c *collector) approvers(pr *PullRequest, reviews []ghReview, authors map[string]bool, subject string) []string {
	sort.SliceStable(reviews, func(a, b int) bool {
		x, y := reviews[a], reviews[b]
		if x.SubmittedAt != nil && y.SubmittedAt != nil && !x.SubmittedAt.Equal(*y.SubmittedAt) {
			return x.SubmittedAt.Before(*y.SubmittedAt)
		}
		return x.ID < y.ID
	})
	latest := map[string]ghReview{}
	for _, r := range reviews {
		rv := Review{User: login(r.User), State: r.State, Commit: r.CommitID}
		if r.SubmittedAt != nil {
			rv.SubmittedAt = ts(*r.SubmittedAt)
		}
		pr.Reviews = append(pr.Reviews, rv)
		switch r.State {
		case "APPROVED", "CHANGES_REQUESTED", "DISMISSED":
			latest[rv.User] = r
		}
	}
	var ok, self, stale []string
	for u, r := range latest {
		if r.State != "APPROVED" {
			continue
		}
		switch {
		case authors[u]:
			self = append(self, u)
		case r.CommitID != pr.Head:
			stale = append(stale, u)
		default:
			ok = append(ok, u)
		}
	}
	if len(ok) > 0 {
		return ok
	}
	slices.Sort(self)
	slices.Sort(stale)
	switch {
	case len(self) > 0:
		c.find(Finding{Code: SelfApproval, Subject: subject, Detail: "approved only by the author or a commit author: " + strings.Join(self, ", ")})
	case len(stale) > 0:
		c.find(Finding{Code: StaleApproval, Subject: subject, Detail: "approved an earlier commit than the merged head " + pr.Head + ": " + strings.Join(stale, ", ")})
	default:
		c.find(Finding{Code: NoApproval, Subject: subject, Detail: "merged without an approving review"})
	}
	return nil
}

// checks are the required checks' runs on sha.
func (c *collector) checks(ctx context.Context, repo, sha, subject string) ([]Check, error) {
	runs := map[string]ghCheckRun{}
	if err := c.gh.list(ctx, "/repos/"+repo+"/commits/"+sha+"/check-runs", nil, "check_runs", func(raw json.RawMessage) error {
		var r ghCheckRun
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		if old, ok := runs[r.Name]; !ok || r.ID > old.ID {
			runs[r.Name] = r
		}
		return nil
	}); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var out []Check
	for _, name := range c.o.RequiredChecks {
		r, ok := runs[name]
		if !ok {
			out = append(out, Check{Name: name, Conclusion: "missing"})
			c.find(Finding{Code: CheckMissing, Subject: subject, Detail: name + ": no run on " + sha})
			continue
		}
		con := r.Conclusion
		if r.Status != "completed" || con == "" {
			con = r.Status
		}
		out = append(out, Check{Name: name, Conclusion: con, URL: r.HTMLURL})
		switch con {
		case "success", "neutral", "skipped": // what GitHub accepts for a required check
		default:
			c.find(Finding{Code: CheckFailed, Subject: subject, Detail: name + ": " + con})
		}
	}
	return out, nil
}

// releases records each release published in the period, deployed in it,
// or named in Options.Releases.
func (c *collector) releases(ctx context.Context, ds []Deployment) (map[string]*Release, error) {
	var all []ghRelease
	if err := c.gh.list(ctx, "/repos/"+c.o.Repository+"/releases", nil, "", func(raw json.RawMessage) error {
		var r ghRelease
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		if !r.Draft && r.PublishedAt != nil {
			all = append(all, r)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Slice(all, func(a, b int) bool { return all[a].PublishedAt.Before(*all[b].PublishedAt) })
	byTag := map[string]int{}
	want := map[string]bool{}
	for i, r := range all {
		byTag[r.TagName] = i
		if !r.PublishedAt.Before(c.o.From) && r.PublishedAt.Before(c.o.To) {
			want[r.TagName] = true
		}
	}
	for _, d := range ds {
		want[d.Release] = true
	}
	for _, t := range c.o.Releases {
		want[t] = true
	}
	tags := make([]string, 0, len(want))
	for t := range want {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	out := map[string]*Release{}
	for _, tag := range tags {
		i, ok := byTag[tag]
		if !ok {
			c.find(Finding{Code: ReleaseNotFound, Subject: Subject("release", tag), Release: tag, Detail: "no published release " + tag + " in " + c.o.Repository})
			continue
		}
		prev := ""
		if i > 0 {
			prev = all[i-1].TagName
		}
		x, err := c.release(ctx, all[i], prev)
		if err != nil {
			return nil, err
		}
		out[tag] = x
	}
	return out, nil
}

func (c *collector) release(ctx context.Context, r ghRelease, prev string) (*Release, error) {
	repo := c.o.Repository
	subject := Subject("release", r.TagName)
	x := &Release{Tag: r.TagName, URL: r.HTMLURL, PublishedAt: ts(*r.PublishedAt), Prerelease: r.Prerelease}
	var cm ghCommit
	if err := c.gh.get(ctx, "/repos/"+repo+"/commits/"+url.PathEscape(r.TagName), nil, &cm); err != nil {
		return nil, err
	}
	x.Commit = cm.SHA
	if err := c.signatures(ctx, r, x, subject); err != nil {
		return nil, err
	}
	if err := c.releaseRun(ctx, x, subject); err != nil {
		return nil, err
	}
	x.Previous = prev
	if x.Previous == "" {
		x.Previous = c.o.FirstBase
	}
	if x.Previous == "" {
		c.find(Finding{Code: ReleaseBaseUnknown, Subject: subject, Release: x.Tag, Detail: "the first release: its commits are not paired with pull requests (give the first base commit)"})
		return x, nil
	}
	var shas []string
	path := "/repos/" + repo + "/compare/" + url.PathEscape(x.Previous) + "..." + url.PathEscape(x.Tag)
	if err := c.gh.list(ctx, path, nil, "commits", func(raw json.RawMessage) error {
		var cm ghCommit
		if err := json.Unmarshal(raw, &cm); err != nil {
			return err
		}
		shas = append(shas, cm.SHA)
		return nil
	}); err != nil {
		return nil, err
	}
	x.Commits = len(shas)
	for _, sha := range shas {
		pr, err := c.pullFor(ctx, repo, sha)
		if err != nil {
			return nil, err
		}
		if pr == nil {
			c.find(Finding{Code: CommitWithoutPR, Subject: Subject("commit", repo+"@"+sha), Release: x.Tag, Detail: "in " + x.Tag + " without a merged pull request"})
			continue
		}
		x.PullRequests = append(x.PullRequests, pr.ID)
	}
	return x, nil
}

// signatures checks the release's manifest, SHA256SUMS and cosign.pub
// against the release key.
func (c *collector) signatures(ctx context.Context, r ghRelease, x *Release, subject string) error {
	assets := map[string]string{}
	for _, a := range r.Assets {
		assets[a.Name] = a.URL
	}
	get := func(name string) ([]byte, error) {
		u, ok := assets[name]
		if !ok {
			return nil, nil
		}
		return c.gh.asset(ctx, u)
	}
	f := func(code, detail string) {
		c.find(Finding{Code: code, Subject: subject, Release: x.Tag, Detail: detail})
	}
	manifest, err := get("release-manifest.json")
	if err != nil {
		return err
	}
	msig, err := get("release-manifest.json.sig")
	if err != nil {
		return err
	}
	switch {
	case manifest == nil || msig == nil:
		x.ManifestSignature = "missing"
		f(ReleaseUnsigned, "release-manifest.json or its signature is not in the release")
	default:
		d := sha256.Sum256(manifest)
		x.Manifest = hex.EncodeToString(d[:])
		m, err := releasemanifest.Verify(c.o.ReleaseKey, manifest, msig)
		if err != nil {
			x.ManifestSignature = "invalid"
			f(ReleaseSignatureInvalid, "release-manifest.json: "+err.Error())
			break
		}
		x.ManifestSignature = "verified"
		x.Images = m.Images
		if m.Release != x.Tag {
			f(ReleaseManifestMismatch, "the signed manifest is for release "+m.Release)
		}
	}
	sums, err := get("SHA256SUMS")
	if err != nil {
		return err
	}
	ssig, err := get("SHA256SUMS.sig")
	if err != nil {
		return err
	}
	switch {
	case sums == nil || ssig == nil:
		x.SumsSignature = "missing"
		f(ReleaseSumsUnsigned, "SHA256SUMS or its signature is not in the release")
	case profilepkg.VerifySignature(c.o.ReleaseKey, sums, ssig) != nil:
		x.SumsSignature = "invalid"
		f(ReleaseSumsInvalid, "SHA256SUMS: the signature does not verify with the release key")
	default:
		x.SumsSignature = "verified"
		if x.Manifest != "" && sumOf(sums, "release-manifest.json") != x.Manifest {
			x.SumsSignature = "invalid"
			f(ReleaseSumsInvalid, "SHA256SUMS does not list release-manifest.json with its digest")
		}
	}
	pub, err := get("cosign.pub")
	if err != nil {
		return err
	}
	switch {
	case pub == nil:
		x.ReleaseKey = "missing"
		f(ReleaseKeyMismatch, "cosign.pub is not in the release")
	case !samePublic(pub, c.o.ReleaseKey):
		x.ReleaseKey = "differs"
		f(ReleaseKeyMismatch, "the release's cosign.pub is not the release key")
	default:
		x.ReleaseKey = "matches"
	}
	return nil
}

func sumOf(sums []byte, name string) string {
	s := bufio.NewScanner(bytes.NewReader(sums))
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return f[0]
		}
	}
	return ""
}

func samePublic(pemBytes []byte, key *ecdsa.PublicKey) bool {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return false
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return false
	}
	e, ok := k.(*ecdsa.PublicKey)
	return ok && e.Equal(key)
}

// releaseRun is the release workflow's latest run for the tag and the
// outcome of the jobs that sign, attest and verify it.
func (c *collector) releaseRun(ctx context.Context, x *Release, subject string) error {
	var run *ghRun
	q := url.Values{"event": {"push"}, "head_sha": {x.Commit}}
	if err := c.gh.list(ctx, "/repos/"+c.o.Repository+"/actions/workflows/"+c.o.ReleaseWorkflow+"/runs", q, "workflow_runs", func(raw json.RawMessage) error {
		var r ghRun
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		if r.HeadBranch == x.Tag && (run == nil || r.ID > run.ID) {
			run = &r
		}
		return nil
	}); err != nil {
		return err
	}
	if run == nil {
		c.find(Finding{Code: ReleaseRunMissing, Subject: subject, Release: x.Tag, Detail: "no " + c.o.ReleaseWorkflow + " run for the tag"})
		return nil
	}
	jobs, err := c.jobs(ctx, run.ID)
	if err != nil {
		return err
	}
	x.Run = &Run{ID: run.ID, URL: run.HTMLURL, Commit: run.HeadSHA, Conclusion: conclusion(run.Status, run.Conclusion)}
	for _, j := range jobs {
		x.Run.Jobs = append(x.Run.Jobs, Job{Name: j.Name, Conclusion: conclusion(j.Status, j.Conclusion)})
	}
	for _, want := range c.o.ReleaseJobs {
		var seen, bad []string
		for _, j := range x.Run.Jobs {
			if j.Name == want || strings.HasPrefix(j.Name, want+" (") || strings.HasPrefix(j.Name, want+" / ") {
				seen = append(seen, j.Name)
				if j.Conclusion != "success" {
					bad = append(bad, j.Name+": "+j.Conclusion)
				}
			}
		}
		switch {
		case len(seen) == 0:
			c.find(Finding{Code: ReleaseJobMissing, Subject: subject, Release: x.Tag, Detail: want + ": not in run " + fmt.Sprint(run.ID)})
		case len(bad) > 0:
			slices.Sort(bad)
			c.find(Finding{Code: ReleaseJobFailed, Subject: subject, Release: x.Tag, Detail: strings.Join(bad, "; ")})
		}
	}
	return nil
}

func (c *collector) jobs(ctx context.Context, run int64) ([]ghJob, error) {
	var out []ghJob
	err := c.gh.list(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d/jobs", c.o.Repository, run), url.Values{"filter": {"latest"}}, "jobs", func(raw json.RawMessage) error {
		var j ghJob
		if err := json.Unmarshal(raw, &j); err != nil {
			return err
		}
		out = append(out, j)
		return nil
	})
	return out, err
}

func conclusion(status, con string) string {
	if status != "completed" || con == "" {
		return status
	}
	return con
}

// pairDeployments pairs each rollout with its release and with the fleet
// repository's approved pull request that pinned it.
func (c *collector) pairDeployments(ctx context.Context, ds []Deployment, rels map[string]*Release) error {
	for i := range ds {
		d := &ds[i]
		subject := Subject("deployment", d.ID)
		f := func(code, detail string) {
			c.find(Finding{Code: code, Subject: subject, Instance: d.Instance, Release: d.Release, Detail: detail})
		}
		switch d.Status {
		case "failed":
			f(DeploymentFailed, fmt.Sprintf("never reconciled; error events: %d", d.Errors))
		case "incomplete":
			f(DeploymentIncomplete, "not reconciled by the end of the period")
		}
		x, ok := rels[d.Release]
		switch {
		case !ok:
			f(DeploymentUnknown, "release "+d.Release+" is not a published release")
		case x.ManifestSignature != "verified":
			f(DeploymentUnsigned, "release "+d.Release+": manifest signature "+x.ManifestSignature)
		}
		switch {
		case d.FleetCommit == "":
			f(DeploymentNoFleetCommit, "no fleet repository revision was applied before the rollout")
		case c.o.FleetRepository == "":
			f(FleetNotChecked, "the fleet repository was not given; commit "+d.FleetCommit+" not paired")
		default:
			pr, err := c.pullFor(ctx, c.o.FleetRepository, d.FleetCommit)
			if err != nil {
				return err
			}
			if pr == nil {
				f(DeploymentNoPR, "fleet commit "+d.FleetCommit+" has no merged pull request")
				break
			}
			d.FleetPullRequest = pr.ID
			if len(pr.Approvers) == 0 {
				f(DeploymentUnapproved, "fleet pull request "+pr.ID+" has no approval by another person")
			}
		}
	}
	return nil
}

var applyName = regexp.MustCompile(`^(.+) \(([^()]+)\)$`)

// applies records each instance apply of the infrastructure workflow's
// runs on the branch in the period, with the protected environment's
// approvals.
func (c *collector) applies(ctx context.Context) ([]Apply, error) {
	repo := c.o.Repository
	var runs []ghRun
	q := url.Values{
		"event":   {"push"},
		"branch":  {c.o.Branch},
		"created": {ts(c.o.From) + ".." + ts(c.o.To.Add(-time.Second))},
	}
	if err := c.gh.list(ctx, "/repos/"+repo+"/actions/workflows/"+c.o.InfraWorkflow+"/runs", q, "workflow_runs", func(raw json.RawMessage) error {
		var r ghRun
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		runs = append(runs, r)
		return nil
	}); err != nil {
		return nil, err
	}
	var out []Apply
	for _, run := range runs {
		jobs, err := c.jobs(ctx, run.ID)
		if err != nil {
			return nil, err
		}
		var applyJobs []ghJob
		for _, j := range jobs {
			if m := applyName.FindStringSubmatch(j.Name); m != nil && m[1] == c.o.ApplyJob {
				applyJobs = append(applyJobs, j)
			}
		}
		if len(applyJobs) == 0 {
			continue // nothing to apply in this run
		}
		var approvals []ghApproval
		if err := c.gh.get(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d/approvals", repo, run.ID), nil, &approvals); err != nil {
			return nil, err
		}
		trigger := login(run.TriggeringActor)
		if trigger == "" {
			trigger = login(run.Actor)
		}
		var recorded []Approval
		var approved, selfApproved, rejected []string
		for _, a := range approvals {
			if !slices.ContainsFunc(a.Environments, func(e ghEnvironment) bool { return e.Name == c.o.Environment }) {
				continue
			}
			u := login(a.User)
			recorded = append(recorded, Approval{User: u, State: a.State, Comment: a.Comment})
			switch {
			case a.State == "approved" && u == trigger:
				selfApproved = append(selfApproved, u)
			case a.State == "approved":
				approved = append(approved, u)
			case a.State == "rejected":
				rejected = append(rejected, u)
			}
		}
		pr, err := c.pullFor(ctx, repo, run.HeadSHA)
		if err != nil {
			return nil, err
		}
		for _, j := range applyJobs {
			inst := applyName.FindStringSubmatch(j.Name)[2]
			a := Apply{
				ID: fmt.Sprintf("%s:%d", inst, run.ID), Instance: inst, Run: run.ID, URL: run.HTMLURL, Commit: run.HeadSHA,
				CreatedAt: ts(run.CreatedAt), TriggeredBy: trigger, Conclusion: conclusion(j.Status, j.Conclusion),
				Approvals: recorded,
			}
			subject := Subject("apply", a.ID)
			f := func(code, detail string) {
				c.find(Finding{Code: code, Subject: subject, Instance: inst, Detail: detail})
			}
			if pr != nil {
				a.PullRequest = pr.ID
			} else {
				f(ApplyNoPR, "commit "+run.HeadSHA+" has no merged pull request")
			}
			ran := a.Conclusion == "success" || a.Conclusion == "failure"
			switch {
			case ran && len(approved) == 0 && len(selfApproved) > 0:
				f(ApplySelfApproved, "approved only by the person who started the run: "+strings.Join(selfApproved, ", "))
			case ran && len(approved) == 0:
				f(ApplyUnapproved, "ran without an approval of environment "+c.o.Environment)
			}
			switch {
			case a.Conclusion == "failure":
				f(ApplyFailed, "the apply failed")
			case !ran && len(rejected) > 0:
				f(ApplyNotCompleted, "rejected by "+strings.Join(rejected, ", ")+"; the merged change is not applied")
			case !ran:
				f(ApplyNotCompleted, "the apply did not run ("+a.Conclusion+"); the merged change is not applied")
			}
			out = append(out, a)
		}
	}
	return out, nil
}

// only keeps what concerns one instance: its deployments and applies, the
// releases it ran, and the pull requests behind them.
func (r *Report) only(inst string) {
	keep := map[string]bool{}
	rels := map[string]bool{}
	var ds []Deployment
	for _, d := range r.Deployments {
		if d.Instance == inst {
			ds = append(ds, d)
			rels[d.Release] = true
			keep[Subject("deployment", d.ID)] = true
			if d.FleetPullRequest != "" {
				keep[Subject("pull_request", d.FleetPullRequest)] = true
			}
		}
	}
	var as []Apply
	for _, a := range r.Applies {
		if a.Instance == inst {
			as = append(as, a)
			keep[Subject("apply", a.ID)] = true
			if a.PullRequest != "" {
				keep[Subject("pull_request", a.PullRequest)] = true
			}
		}
	}
	var xs []Release
	for _, x := range r.Releases {
		if rels[x.Tag] {
			xs = append(xs, x)
			keep[Subject("release", x.Tag)] = true
			for _, p := range x.PullRequests {
				keep[Subject("pull_request", p)] = true
			}
		}
	}
	var ps []PullRequest
	for _, p := range r.PullRequests {
		if keep[Subject("pull_request", p.ID)] {
			ps = append(ps, p)
		}
	}
	var fs []Finding
	for _, f := range r.Findings {
		if keep[f.Subject] || f.Instance == inst || (f.Instance == "" && f.Release != "" && rels[f.Release]) {
			fs = append(fs, f)
		}
	}
	r.Deployments, r.Applies, r.Releases, r.PullRequests, r.Findings = ds, as, xs, ps, fs
}
