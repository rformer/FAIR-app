// Package releasemanifest is the platform release manifest (F-015 T-28,
// design §6.8): the expected state the deployment scanner compares the
// cluster with. It names the image, by digest, of each platform component
// and holds a SHA-256 of each platform RBAC object's normalized content.
// The release pipeline builds it (cmd/releasegen) from deploy/k8s and the
// built images' digests, and signs it with the release key (detached
// ECDSA P-256 signature, as profile packages); the scanner verifies the
// signature before using it.
package releasemanifest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/rformer/fair-app/internal/profilepkg"
)

// Format identifies the manifest format.
const Format = "fair-platform-release-manifest/v1"

// Manifest is the expected state of one platform release.
type Manifest struct {
	Format  string            `json:"format"`
	Release string            `json:"release"`
	Images  map[string]string `json:"images"` // component -> repository@sha256:<digest>
	RBAC    []RBACEntry       `json:"rbac"`
}

// RBACEntry is one platform RBAC object and the hash of its normalized
// rules (roles) or role reference and subjects (bindings).
type RBACEntry struct {
	Kind      string `json:"kind"` // Role, ClusterRole, RoleBinding, ClusterRoleBinding
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
}

// Key identifies an RBAC object.
func (e RBACEntry) Key() string { return e.Kind + "/" + e.Namespace + "/" + e.Name }

// RBACKinds are the kinds the manifest covers.
var RBACKinds = []string{"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}

var imageRE = regexp.MustCompile(`^[a-z0-9.\-/:]+@sha256:[0-9a-f]{64}$`)

// Validate checks the manifest's shape.
func (m *Manifest) Validate() error {
	if m.Format != Format {
		return fmt.Errorf("releasemanifest: format %q, want %q", m.Format, Format)
	}
	if m.Release == "" || len(m.Images) == 0 {
		return errors.New("releasemanifest: release and images are required")
	}
	for c, img := range m.Images {
		if c == "" || !imageRE.MatchString(img) {
			return fmt.Errorf("releasemanifest: image %q for %q must be repository@sha256:<digest>", img, c)
		}
	}
	seen := map[string]bool{}
	for _, e := range m.RBAC {
		if !slices.Contains(RBACKinds, e.Kind) || e.Name == "" || len(e.SHA256) != 64 || seen[e.Key()] {
			return fmt.Errorf("releasemanifest: invalid or duplicate RBAC entry %+v", e)
		}
		if (e.Kind == "Role" || e.Kind == "RoleBinding") != (e.Namespace != "") {
			return fmt.Errorf("releasemanifest: %s %s: namespace mismatch", e.Kind, e.Name)
		}
		seen[e.Key()] = true
	}
	return nil
}

// Repository is an image reference without tag or digest.
func Repository(image string) string {
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		image = image[:i]
	}
	return image
}

// Digest is the sha256:<hex> of an image reference or image ID, or "".
func Digest(ref string) string {
	if i := strings.Index(ref, "@sha256:"); i >= 0 {
		return ref[i+1:]
	}
	if strings.HasPrefix(ref, "sha256:") {
		return ref
	}
	return ""
}

// rule and subject are the normalized forms that are hashed.
type rule struct {
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	Verbs           []string `json:"verbs"`
	ResourceNames   []string `json:"resourceNames"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

type subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Hash returns the SHA-256 of an RBAC object's normalized content, from its
// JSON (as the API server returns it, or converted from YAML). Field order,
// list order and defaulted subject apiGroups do not change it.
func Hash(kind string, obj []byte) (string, error) {
	var o struct {
		Rules           []rule          `json:"rules"`
		AggregationRule json.RawMessage `json:"aggregationRule"`
		RoleRef         struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"roleRef"`
		Subjects []subject `json:"subjects"`
	}
	if err := json.Unmarshal(obj, &o); err != nil {
		return "", fmt.Errorf("releasemanifest: %s: %w", kind, err)
	}
	var norm any
	switch kind {
	case "Role", "ClusterRole":
		rules := make([]string, 0, len(o.Rules))
		for _, r := range o.Rules {
			for _, l := range [][]string{r.APIGroups, r.Resources, r.Verbs, r.ResourceNames, r.NonResourceURLs} {
				sort.Strings(l)
			}
			r.APIGroups, r.Resources, r.Verbs = nonNil(r.APIGroups), nonNil(r.Resources), nonNil(r.Verbs)
			r.ResourceNames, r.NonResourceURLs = nonNil(r.ResourceNames), nonNil(r.NonResourceURLs)
			b, _ := json.Marshal(r)
			rules = append(rules, string(b))
		}
		sort.Strings(rules)
		agg := ""
		if len(o.AggregationRule) > 0 && string(o.AggregationRule) != "null" {
			var c bytes.Buffer
			if err := json.Compact(&c, o.AggregationRule); err != nil {
				return "", err
			}
			agg = c.String()
		}
		norm = map[string]any{"rules": rules, "aggregationRule": agg}
	case "RoleBinding", "ClusterRoleBinding":
		subs := make([]string, 0, len(o.Subjects))
		for _, s := range o.Subjects {
			b, _ := json.Marshal(s)
			subs = append(subs, string(b))
		}
		sort.Strings(subs)
		norm = map[string]any{"roleRef": o.RoleRef.Kind + "/" + o.RoleRef.Name, "subjects": subs}
	default:
		return "", fmt.Errorf("releasemanifest: %s is not an RBAC kind", kind)
	}
	b, _ := json.Marshal(norm)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// RBACFromDir hashes every RBAC object in the YAML files of the given
// directories (not their subdirectories): deploy/k8s, plus a platform's own
// directory such as deploy/k8s/openshift for that platform's releases.
func RBACFromDir(dirs ...string) ([]RBACEntry, error) {
	var files []string
	for _, dir := range dirs {
		fs, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			return nil, err
		}
		files = append(files, fs...)
	}
	sort.Strings(files)
	var out []RBACEntry
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- build-time input directory
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		for {
			var d map[string]any
			if err := dec.Decode(&d); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			kind, _ := d["kind"].(string)
			if !slices.Contains(RBACKinds, kind) {
				continue
			}
			meta, _ := d["metadata"].(map[string]any)
			name, _ := meta["name"].(string)
			ns, _ := meta["namespace"].(string)
			j, err := json.Marshal(d)
			if err != nil {
				return nil, fmt.Errorf("%s: %s %s: %w", f, kind, name, err)
			}
			h, err := Hash(kind, j)
			if err != nil {
				return nil, err
			}
			out = append(out, RBACEntry{Kind: kind, Namespace: ns, Name: name, SHA256: h})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}

// Encode returns the manifest's canonical bytes (what is signed).
func Encode(m *Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return profilepkg.Encode(m)
}

// Verify checks the detached signature with the release public key and
// returns the manifest. Nothing in an unverified manifest is used.
func Verify(pub *ecdsa.PublicKey, b, sig []byte) (*Manifest, error) {
	if err := profilepkg.VerifySignature(pub, b, sig); err != nil {
		return nil, fmt.Errorf("releasemanifest: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("releasemanifest: %w", err)
	}
	return &m, m.Validate()
}

// Load reads and verifies a manifest and its signature (file + ".sig").
func Load(pub *ecdsa.PublicKey, file string) (*Manifest, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- mounted release manifest
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(file + ".sig") // #nosec G304 -- its detached signature
	if err != nil {
		return nil, err
	}
	return Verify(pub, b, sig)
}
