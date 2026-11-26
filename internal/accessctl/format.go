// Package accessctl applies and expires just-in-time operator access to the
// SaaS instances (F-012 T-18, F-012-AC-27, design §3.9). Nobody holds
// standing access to an instance account: an operator asks for it with a
// pull request adding access/requests/<id>.yaml to the fleet repository,
// a second operator approves it (code owners), and accessctl:
//
//   - grants it: an IAM Identity Center account assignment of the role's
//     permission set (FairReadOnly or FairOperator, infra/modules/
//     operator-access: neither may read customer data) to the operator in
//     the instance's account, and an EKS access entry for the role the
//     assignment provisions (the view policy; operators also the Kubernetes
//     group fair:operator, deploy/fleet/addons-config/operator-access.yaml);
//   - expires it: every run removes each assignment to a FAIR permission set
//     and each FAIR access entry that no active request backs (expired,
//     revoked, never requested, or assigned by hand), so access ends at
//     start + duration (at most 8 hours) even if a grant or a revocation
//     was missed;
//   - records each change as a JSON line (and CloudTrail records the calls).
//
// The AWS clients are behind small interfaces (fakes in tests). The real
// ones use FIPS endpoints in the GovCloud partition and credentials only
// from a web identity token file (the workflow's OIDC token), as
// internal/kmssign does; no access key is read.
package accessctl

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

// RequestSchema is the request format's JSON Schema (fair.access-request.v1);
// deploy/fleet/access/request.schema.json is a copy (test-enforced).
//
//go:embed request.schema.json
var RequestSchema []byte

// Formats of the files in the access directory.
const (
	RequestFormat    = "fair.access-request.v1"
	OperatorsFormat  = "fair.access-operators.v1"
	InstancesFormat  = "fair.access-instances.v1"
	ControllerFormat = "fair.access-controller.v1"
)

// MaxDuration bounds every request (design §3.9).
const MaxDuration = 8 * time.Hour

// Roles a request may ask for.
const (
	RoleReadOnly = "read-only"
	RoleOperator = "operator"
)

// Roles in a fixed order.
var Roles = []string{RoleReadOnly, RoleOperator}

// OperatorGroup is the Kubernetes group of the operator role's access entry;
// its RBAC is deploy/fleet/addons-config/operator-access.yaml.
const OperatorGroup = "fair:operator"

// Revocation ends a request early (added by a later pull request).
type Revocation struct {
	At     string `yaml:"at" json:"at"`
	By     string `yaml:"by" json:"by"`
	Reason string `yaml:"reason" json:"reason"`
}

// Request is one access request (access/requests/<ID>.yaml).
type Request struct {
	ID       string      `yaml:"-" json:"id"`
	Format   string      `yaml:"format" json:"format"`
	Operator string      `yaml:"operator" json:"operator"`
	Approver string      `yaml:"approver" json:"approver"`
	Instance string      `yaml:"instance" json:"instance"`
	Role     string      `yaml:"role" json:"role"`
	Reason   string      `yaml:"reason" json:"reason"`
	Ticket   string      `yaml:"ticket" json:"ticket"`
	Start    string      `yaml:"start" json:"start"`
	Duration string      `yaml:"duration" json:"duration"`
	Revoked  *Revocation `yaml:"revoked,omitempty" json:"revoked,omitempty"`

	start, end time.Time
}

// Window is when the request's access may exist: [start, end). A revocation
// ends it at the revocation's time.
func (r *Request) Window() (start, end time.Time) {
	end = r.end
	if r.Revoked != nil {
		if at, err := time.Parse(time.RFC3339, r.Revoked.At); err == nil && at.Before(end) {
			end = at
		}
	}
	return r.start, end
}

// ActiveAt reports whether the access may exist at t.
func (r *Request) ActiveAt(t time.Time) bool {
	s, e := r.Window()
	return !t.Before(s) && t.Before(e)
}

// Expires is when the access ends.
func (r *Request) Expires() time.Time {
	_, e := r.Window()
	return e
}

// Operator is a person who may hold or approve access.
type Operator struct {
	Name string `yaml:"name"`
	// GitHub is their GitHub login (the pull request's approver).
	GitHub string `yaml:"github"`
	// UserID is their IAM Identity Center user id (the assignment's principal).
	UserID string `yaml:"user_id"`
}

// Instance is where one SaaS instance runs (infra/instance outputs).
type Instance struct {
	AccountID string `yaml:"account_id"`
	Region    string `yaml:"region"`
	Cluster   string `yaml:"cluster"`
}

// PermissionSet is one role's IAM Identity Center permission set
// (infra/ops output operator_access).
type PermissionSet struct {
	ARN  string `yaml:"arn"`
	Name string `yaml:"name"`
}

// ControllerConfig is accessctl's configuration (access/controller.yaml).
type ControllerConfig struct {
	Format    string `yaml:"format"`
	Partition string `yaml:"partition"`
	// Region is IAM Identity Center's region.
	Region string `yaml:"region"`
	// InstanceARN is the IAM Identity Center instance.
	InstanceARN    string                   `yaml:"instance_arn"`
	PermissionSets map[string]PermissionSet `yaml:"permission_sets"`
	// EKSRole is the role accessctl assumes in each instance account to
	// manage the cluster's access entries (infra/instance: fair-access-eks).
	EKSRole string `yaml:"eks_role"`
}

// Dir is a loaded access directory.
type Dir struct {
	Controller ControllerConfig
	Operators  map[string]Operator
	Instances  map[string]Instance
	Requests   map[string]*Request
}

// SortedRequests returns the requests by id.
func (d *Dir) SortedRequests() []*Request {
	out := make([]*Request, 0, len(d.Requests))
	for _, r := range d.Requests {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Active returns the requests active at t for an instance and role.
func (d *Dir) Active(t time.Time, instance, role string) []*Request {
	var out []*Request
	for _, r := range d.SortedRequests() {
		if r.Instance == instance && r.Role == role && r.ActiveAt(t) {
			out = append(out, r)
		}
	}
	return out
}

var (
	instanceRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,19}[a-z0-9]$`)
	idRE        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
	nameRE      = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}$`)
	githubRE    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	userIDRE    = regexp.MustCompile(`^([0-9a-f]{10}-|)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	accountRE   = regexp.MustCompile(`^[0-9]{12}$`)
	regionRE    = regexp.MustCompile(`^us-gov-(west|east)-1$`)
	clusterRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$`)
	psNameRE    = regexp.MustCompile(`^[A-Za-z0-9+=,.@-]{1,32}$`)
	roleNameRE  = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)
	instanceARN = regexp.MustCompile(`^arn:aws-us-gov:sso:::instance/(sso)?ins-[a-zA-Z0-9-.]{16}$`)
	psARN       = regexp.MustCompile(`^arn:aws-us-gov:sso:::permissionSet/(sso)?ins-[a-zA-Z0-9-.]{16}/ps-[a-zA-Z0-9-./]{16}$`)
)

// Load reads and checks an access directory: controller.yaml,
// operators.yaml, instances.yaml and requests/*.yaml. Every problem is
// reported, not just the first.
func Load(dir string) (*Dir, error) {
	d := &Dir{Operators: map[string]Operator{}, Instances: map[string]Instance{}, Requests: map[string]*Request{}}
	var errs []error
	if err := loadControllerFile(filepath.Join(dir, "controller.yaml"), &d.Controller); err != nil {
		errs = append(errs, err)
	}
	if err := loadOperators(filepath.Join(dir, "operators.yaml"), d.Operators); err != nil {
		errs = append(errs, err)
	}
	if err := loadInstances(filepath.Join(dir, "instances.yaml"), d.Instances); err != nil {
		errs = append(errs, err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "requests", "*"))
	if err != nil {
		errs = append(errs, err)
	}
	sort.Strings(files)
	for _, f := range files {
		base := filepath.Base(f)
		if strings.HasPrefix(base, ".") {
			continue
		}
		id, ok := strings.CutSuffix(base, ".yaml")
		if !ok {
			errs = append(errs, fmt.Errorf("requests/%s: requests are <id>.yaml", base))
			continue
		}
		r, err := ReadRequest(f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		r.ID = id
		if err := d.checkRequest(r); err != nil {
			errs = append(errs, fmt.Errorf("requests/%s: %w", base, err))
			continue
		}
		d.Requests[id] = r
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return d, nil
}

func strict(path string, v any) error {
	b, err := os.ReadFile(path) // #nosec G304 -- the access directory the operator names
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}

func loadControllerFile(path string, c *ControllerConfig) error {
	if err := strict(path, c); err != nil {
		return err
	}
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf("controller.yaml: "+f, a...)) }
	if c.Format != ControllerFormat {
		bad("format is %q, not %s", c.Format, ControllerFormat)
	}
	if c.Partition != "aws-us-gov" {
		bad("partition is %q: the SaaS runs in GovCloud (aws-us-gov)", c.Partition)
	}
	if !regionRE.MatchString(c.Region) {
		bad("region %q is not a GovCloud region", c.Region)
	}
	if !instanceARN.MatchString(c.InstanceARN) {
		bad("instance_arn %q is not an IAM Identity Center instance in GovCloud", c.InstanceARN)
	}
	if !roleNameRE.MatchString(c.EKSRole) {
		bad("eks_role %q is not a role name", c.EKSRole)
	}
	if len(c.PermissionSets) != len(Roles) {
		bad("permission_sets names exactly %v", Roles)
	}
	names := map[string]bool{}
	for _, role := range Roles {
		ps, ok := c.PermissionSets[role]
		if !ok {
			bad("permission_sets has no %s", role)
			continue
		}
		if !psARN.MatchString(ps.ARN) || !strings.Contains(ps.ARN, strings.TrimPrefix(c.InstanceARN, "arn:aws-us-gov:sso:::instance/")+"/") {
			bad("permission_sets.%s.arn %q is not a permission set of %s", role, ps.ARN, c.InstanceARN)
		}
		if !psNameRE.MatchString(ps.Name) {
			bad("permission_sets.%s.name %q is not a permission set name", role, ps.Name)
		}
		if names[ps.Name] {
			bad("permission_sets.%s.name %q is used twice", role, ps.Name)
		}
		names[ps.Name] = true
	}
	return errors.Join(errs...)
}

func loadOperators(path string, out map[string]Operator) error {
	var f struct {
		Format    string     `yaml:"format"`
		Operators []Operator `yaml:"operators"`
	}
	if err := strict(path, &f); err != nil {
		return err
	}
	var errs []error
	bad := func(s string, a ...any) { errs = append(errs, fmt.Errorf("operators.yaml: "+s, a...)) }
	if f.Format != OperatorsFormat {
		bad("format is %q, not %s", f.Format, OperatorsFormat)
	}
	github, users := map[string]bool{}, map[string]bool{}
	for i, o := range f.Operators {
		switch {
		case !nameRE.MatchString(o.Name):
			bad("operators[%d]: name %q is not lower-case letters, digits and dashes", i, o.Name)
		case !githubRE.MatchString(o.GitHub):
			bad("%s: github %q is not a GitHub login", o.Name, o.GitHub)
		case !userIDRE.MatchString(o.UserID):
			bad("%s: user_id %q is not an IAM Identity Center user id", o.Name, o.UserID)
		case out[o.Name].Name != "":
			bad("%s is listed twice", o.Name)
		case github[strings.ToLower(o.GitHub)] || users[o.UserID]:
			bad("%s: another operator has the same GitHub login or user id (one person, one entry)", o.Name)
		default:
			out[o.Name] = o
			github[strings.ToLower(o.GitHub)] = true
			users[o.UserID] = true
		}
	}
	return errors.Join(errs...)
}

func loadInstances(path string, out map[string]Instance) error {
	var f struct {
		Format    string              `yaml:"format"`
		Instances map[string]Instance `yaml:"instances"`
	}
	if err := strict(path, &f); err != nil {
		return err
	}
	var errs []error
	bad := func(s string, a ...any) { errs = append(errs, fmt.Errorf("instances.yaml: "+s, a...)) }
	if f.Format != InstancesFormat {
		bad("format is %q, not %s", f.Format, InstancesFormat)
	}
	accounts := map[string]string{}
	for name, in := range f.Instances {
		switch {
		case !instanceRE.MatchString(name):
			bad("%q is not an instance id", name)
		case !accountRE.MatchString(in.AccountID):
			bad("%s: account_id %q is not a 12-digit account id", name, in.AccountID)
		case accounts[in.AccountID] != "":
			bad("%s: account %s is also %s's (one account per instance)", name, in.AccountID, accounts[in.AccountID])
		case !regionRE.MatchString(in.Region):
			bad("%s: region %q is not a GovCloud region", name, in.Region)
		case !clusterRE.MatchString(in.Cluster):
			bad("%s: cluster %q is not a cluster name", name, in.Cluster)
		default:
			out[name] = in
			accounts[in.AccountID] = name
		}
	}
	return errors.Join(errs...)
}

var (
	schemaOnce sync.Once
	schema     *jsonschema.Schema
	schemaErr  error
)

func requestSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(RequestSchema))
		if err != nil {
			schemaErr = err
			return
		}
		c := jsonschema.NewCompiler()
		const url = "request.schema.json"
		if err := c.AddResource(url, doc); err != nil {
			schemaErr = err
			return
		}
		schema, schemaErr = c.Compile(url)
	})
	return schema, schemaErr
}

// ReadRequest reads one request and checks it against RequestSchema and
// its own rules (start, duration at most MaxDuration, revocation after the
// start). Whether its names exist is Dir's check.
func ReadRequest(path string) (*Request, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the access directory the operator names
	if err != nil {
		return nil, err
	}
	name := filepath.Base(path)
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("requests/%s: %w", name, err)
	}
	inst, err := jsonValue(&doc)
	if err != nil {
		return nil, fmt.Errorf("requests/%s: %w", name, err)
	}
	s, err := requestSchema()
	if err != nil {
		return nil, fmt.Errorf("request schema: %w", err)
	}
	if err := s.Validate(inst); err != nil {
		return nil, fmt.Errorf("requests/%s: %w", name, err)
	}
	r := &Request{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(r); err != nil {
		return nil, fmt.Errorf("requests/%s: %w", name, err)
	}
	if r.start, err = time.Parse(time.RFC3339, r.Start); err != nil {
		return nil, fmt.Errorf("requests/%s: start: %w", name, err)
	}
	d, err := time.ParseDuration(r.Duration)
	if err != nil {
		return nil, fmt.Errorf("requests/%s: duration: %w", name, err)
	}
	if d <= 0 || d > MaxDuration {
		return nil, fmt.Errorf("requests/%s: duration %s: at most %s", name, r.Duration, MaxDuration)
	}
	r.end = r.start.Add(d)
	if r.Revoked != nil {
		if _, err := time.Parse(time.RFC3339, r.Revoked.At); err != nil {
			return nil, fmt.Errorf("requests/%s: revoked.at: %w", name, err)
		}
	}
	return r, nil
}

// jsonValue turns a YAML document into the JSON value the schema
// validates. Scalars keep their text: a timestamp stays the string written
// (so "start" must be written in UTC to match the schema).
func jsonValue(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return nil, errors.New("one YAML document expected")
		}
		return jsonValue(n.Content[0])
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("line %d: keys are strings", k.Line)
			}
			if _, dup := out[k.Value]; dup {
				return nil, fmt.Errorf("line %d: %s appears twice", k.Line, k.Value)
			}
			v, err := jsonValue(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			out[k.Value] = v
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := jsonValue(c)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!null":
			return nil, nil
		case "!!bool":
			return n.Value == "true", nil
		case "!!int", "!!float":
			return json.Number(n.Value), nil
		default:
			return n.Value, nil
		}
	default:
		return nil, fmt.Errorf("line %d: aliases and anchors are not allowed", n.Line)
	}
}

func (d *Dir) checkRequest(r *Request) error {
	if !idRE.MatchString(r.ID) {
		return fmt.Errorf("the id %q (the file's name) is not lower-case letters, digits and dashes (3 to 63)", r.ID)
	}
	op, ok := d.Operators[r.Operator]
	if !ok {
		return fmt.Errorf("operator %q is not in operators.yaml", r.Operator)
	}
	ap, ok := d.Operators[r.Approver]
	if !ok {
		return fmt.Errorf("approver %q is not in operators.yaml", r.Approver)
	}
	if r.Operator == r.Approver || op.UserID == ap.UserID || strings.EqualFold(op.GitHub, ap.GitHub) {
		return fmt.Errorf("the approver must be a second operator, not %s", r.Operator)
	}
	if _, ok := d.Instances[r.Instance]; !ok {
		return fmt.Errorf("instance %q is not in instances.yaml", r.Instance)
	}
	if r.Revoked != nil {
		if _, ok := d.Operators[r.Revoked.By]; !ok {
			return fmt.Errorf("revoked.by %q is not in operators.yaml", r.Revoked.By)
		}
	}
	return nil
}

// CheckChanges compares a directory with the one it changes (the pull
// request's base): a merged request is a record, so it may not be removed
// or changed, except by adding a revocation.
func CheckChanges(base, head *Dir) error {
	var errs []error
	for id, b := range base.Requests {
		h, ok := head.Requests[id]
		if !ok {
			errs = append(errs, fmt.Errorf("requests/%s.yaml: a merged request is a record and stays (revoke it instead)", id))
			continue
		}
		bb, hh := *b, *h
		if bb.Revoked != nil {
			if hh.Revoked == nil || *hh.Revoked != *bb.Revoked {
				errs = append(errs, fmt.Errorf("requests/%s.yaml: its revocation may not change", id))
			}
		}
		bb.Revoked, hh.Revoked = nil, nil
		if bb != hh {
			errs = append(errs, fmt.Errorf("requests/%s.yaml: a merged request may not change, except by adding revoked", id))
		}
	}
	return errors.Join(errs...)
}
