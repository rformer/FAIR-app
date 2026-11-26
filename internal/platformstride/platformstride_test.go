// Package platformstride holds F-012's STRIDE checks for design §6 (T-19).
// The mitigations live in workflows, scripts and OpenTofu tests as much as
// in Go: these tests check that each one exists, asserts what the row
// claims, and is run by CI, so the threat table cannot outlive its
// mitigations.
package platformstride

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var root = filepath.Join("..", "..")

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- the repository's own files
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func contains(t *testing.T, rel string, wants ...string) {
	t.Helper()
	s := read(t, rel)
	for _, w := range wants {
		if !strings.Contains(s, w) {
			t.Errorf("%s does not contain %q", rel, w)
		}
	}
}

// workflowJob is a job of a workflow, as these checks read it.
type workflowJob struct {
	If    string `yaml:"if"`
	Uses  string `yaml:"uses"`
	Needs any    `yaml:"needs"`
	Steps []struct {
		Run string `yaml:"run"`
	} `yaml:"steps"`
}

func jobs(t *testing.T, rel string) map[string]workflowJob {
	t.Helper()
	var w struct {
		Jobs map[string]workflowJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(read(t, rel)), &w); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return w.Jobs
}

// runs is whether a job's steps run a command containing cmd.
func runs(j workflowJob, cmd string) bool {
	for _, s := range j.Steps {
		if strings.Contains(s.Run, cmd) {
			return true
		}
	}
	return false
}

func needs(j workflowJob, name string) bool {
	switch n := j.Needs.(type) {
	case string:
		return n == name
	case []any:
		for _, v := range n {
			if v == name {
				return true
			}
		}
	}
	return false
}

// tofuRuns are the run blocks of an OpenTofu test file.
func tofuRuns(t *testing.T, rel string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^run "([a-z0-9_]+)"`).FindAllStringSubmatch(read(t, rel), -1) {
		out[m[1]] = true
	}
	return out
}

func requireRuns(t *testing.T, rel string, names ...string) {
	t.Helper()
	have := tofuRuns(t, rel)
	for _, n := range names {
		if !have[n] {
			t.Errorf("%s has no run %q", rel, n)
		}
	}
}

// infraRunInCI: the infra job runs scripts/infra-check.sh, which runs
// tofu test and Checkov over every directory.
func infraRunInCI(t *testing.T) {
	t.Helper()
	if !runs(jobs(t, ".github/workflows/ci.yml")["infra"], "scripts/infra-check.sh") {
		t.Error("ci.yml's infra job does not run scripts/infra-check.sh")
	}
	contains(t, "scripts/infra-check.sh", "tofu", " test", "checkov")
}

// F-012 design §6: "T: an image differs from the source it claims". The
// release attaches SLSA provenance from the generator to every staged
// image, re-attests it with the release key only after checking it names
// the generator, and admission requires provenance naming this repository's
// release workflow at a tag (internal/fleet TestAdmissionPolicy).
func TestProvenanceNamesSource(t *testing.T) {
	rel := jobs(t, ".github/workflows/release.yml")
	p := rel["provenance"]
	if !strings.HasPrefix(p.Uses, "slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v") || !needs(p, "build") {
		t.Errorf("release.yml provenance: uses %q, needs %v", p.Uses, p.Needs)
	}
	if !needs(rel["sign"], "provenance") || !needs(rel["sign"], "reproducible") {
		t.Errorf("release.yml sign does not wait for provenance and reproducible: %v", rel["sign"].Needs)
	}
	contains(t, ".github/workflows/release-sign.yml",
		"--type slsaprovenance",
		`generator_container_slsa3\.yml@refs/tags/v`,
		"verify-attestation")
	contains(t, "deploy/fleet/policy/release.yaml", "https://slsa.dev/provenance/v0.2", ".github/workflows/release.yml")
}

// "S, T: a forged or swapped image runs in SaaS": admission-e2e.sh on kind
// checks that signed images are admitted and unsigned or wrong-source ones
// refused, and runs in CI.
func TestSTRIDEF012Admission(t *testing.T) {
	if !runs(jobs(t, ".github/workflows/ci.yml")["admission-e2e"], "scripts/admission-e2e.sh") {
		t.Error("ci.yml has no admission-e2e job running scripts/admission-e2e.sh")
	}
	s := read(t, "scripts/admission-e2e.sh")
	for _, want := range []string{
		`admitted "the signed release image with its provenance"`,
		`refused "an unsigned image of the release repository"`,
		`refused "an image signed by another key"`,
		`refused "provenance from another source"`,
		`refused "a signed, attested image from another repository"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("admission-e2e.sh does not check %q", want)
		}
	}
}

// "T: an image differs from the source it claims" (also): every release
// builds every image twice on two runners and compares the digests.
func TestSTRIDEF012Reproducible(t *testing.T) {
	if j := jobs(t, ".github/workflows/release.yml")["reproducible"]; j.Uses != "./.github/workflows/reproducible.yml" {
		t.Errorf("release.yml reproducible uses %q", j.Uses)
	}
	c := jobs(t, ".github/workflows/reproducible.yml")["compare"]
	if !runs(c, "diff a/digests b/digests") {
		t.Error("reproducible.yml compare does not compare the two builds' digests")
	}
}

// "E: the release key is misused".
func TestSTRIDEF012ReleaseKey(t *testing.T) {
	requireRuns(t, "infra/modules/release-signing/tests/release_signing.tftest.hcl",
		"an_ecdsa_p256_signing_key", "only_the_signer_signs", "the_signer_role_trusts_only_the_release_workflow_on_a_tag",
		"the_signer_role_may_only_sign_with_this_key", "admin_role_policy_never_signs")
	infraRunInCI(t)
}

// "I: one customer's instance reaches another's data".
func TestSTRIDEF012InstanceIsolation(t *testing.T) {
	requireRuns(t, "infra/modules/instance/tests/instance.tftest.hcl",
		"isolation", "every_store_is_encrypted_under_its_own_key", "no_public_routes_from_private_subnets",
		"external_secrets_reads_only_this_instance", "stores_are_touched_only_by_their_service")
	requireRuns(t, "infra/modules/guardrails/tests/guardrails.tftest.hcl",
		"every_statement_denies", "govcloud_regions_only", "data_is_encrypted_and_never_public")
	requireRuns(t, "infra/instance/tests/instance.tftest.hcl", "applies_stay_in_the_instance_account", "the_management_account_is_never_an_instance")
	infraRunInCI(t)
}

// "E: operators hold standing access to customer data" (with the
// cmd/accessctl tests).
func TestSTRIDEF012OperatorAccess(t *testing.T) {
	requireRuns(t, "infra/modules/operator-access/tests/operator_access.tftest.hcl",
		"two_permission_sets_with_short_sessions", "both_permission_sets_deny_the_data_plane", "the_controller_only_assigns")
	requireRuns(t, "infra/instance/tests/instance.tftest.hcl", "the_access_role_manages_only_operator_entries")
	infraRunInCI(t)
}

// "T, R: unreviewed or unattributed production changes" (with the
// cmd/evidence tests).
func TestSTRIDEF012BranchProtection(t *testing.T) {
	requireRuns(t, "infra/github/tests/ruleset.tftest.hcl",
		"protects_the_default_branch", "a_second_engineer_approves", "every_gate_is_required", "nobody_bypasses_by_default",
		"instance_applies_need_an_approval")
	if !runs(jobs(t, ".github/workflows/ci.yml")["infra"], "scripts/infra-check.sh") {
		t.Error("ci.yml's infra job does not run scripts/infra-check.sh")
	}
}

// "T: infrastructure drifts from code": the daily drift job, and its dry run
// on every pull request.
func TestSTRIDEF012Drift(t *testing.T) {
	if !runs(jobs(t, ".github/workflows/ci.yml")["infra-drift"], "scripts/infra-drift.sh -dry-run") {
		t.Error("ci.yml has no infra-drift job running scripts/infra-drift.sh -dry-run")
	}
	contains(t, ".github/workflows/infra-instances.yml", "schedule:", "-detailed-exitcode")
	requireRuns(t, "infra/instance/tests/instance.tftest.hcl", "the_plan_role_is_read_only")
}

// CP-9 (F-012 T-20): backups and retention are tested, and CI runs the
// tests: stores replicate to the second region, short database backups are
// refused, and a retired instance keeps every retained store.
func TestBackupsAndRetention(t *testing.T) {
	requireRuns(t, "infra/modules/instance/tests/instance.tftest.hcl",
		"stores_replicate_to_the_second_region", "short_backups_refused", "retired_keeps_every_retained_store",
		"the_audit_worm_bucket_is_object_lock_compliance")
	requireRuns(t, "infra/instance/tests/instance.tftest.hcl", "retired_keeps_the_retained_stores", "retention_shorter_than_the_audit_trail_refused")
	infraRunInCI(t)
}
