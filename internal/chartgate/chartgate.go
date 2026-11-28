// Package chartgate is the release gate over the fair-platform chart
// (F-014 T-09, AC-02, AC-03; design §3.2, §3.17): `profilegen release-check
// -chart` and `-package`.
//
// Check renders the chart with the Helm SDK (ADR-019: release tools only)
// for every combination of its switches (the boolean values: the scanner,
// fips-probe, each bundled dependency) and choices (the enumerated values:
// the key store, the mode) that values.schema.json allows, and for each:
//
//   - applies the render to a compliant cluster (compliant-cluster.yaml,
//     plus what fairctl applies at cluster scope for the switched-on
//     bundled dependencies) through internal/scanner/objreader and runs
//     F-015's deployment check catalog (internal/scanner/checks, the
//     scanner's own functions) over it: any finding or check error fails;
//   - requires every image to be named by digest and to be the release's:
//     a platform image equal to the release manifest's for its component,
//     a mirrored third-party image equal to a copy the manifest's mirrors
//     name (F-014 T-10; and, for a package, listed by the package
//     manifest);
//   - requires every RBAC object (hooks and fairctl's cluster-scoped
//     objects included) to be in the release manifest with the same hash,
//     and every manifest entry the combination switches on to be present.
//
// Failures name their reason (Reason*), the subject and the combinations
// they occur in, so a weakened template, a changed image or an added RBAC
// object is refused by name.
package chartgate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed" // the compliant cluster fixture
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"os"
	"regexp"
	"runtime"
	"slices"

	"strings"
	"sync"
	"time"

	"helm.sh/helm/v4/pkg/chart/common"
	chartutil "helm.sh/helm/v4/pkg/chart/common/util"
	chart "helm.sh/helm/v4/pkg/chart/v2"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	"helm.sh/helm/v4/pkg/engine"

	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/checks"
	"github.com/rformer/fair-app/internal/scanner/kube"
	"github.com/rformer/fair-app/internal/scanner/objreader"
)

// CompliantCluster is the cluster every render is applied to.
//
//go:embed compliant-cluster.yaml
var CompliantCluster []byte

// ProbeNamespace is fips-probe's namespace (the scanner's Scope).
const ProbeNamespace = "fair-fips-probe"

// Failure areas: the release-check rows.
const (
	AreaRender = "render" // the chart renders every combination
	AreaChecks = "checks" // F-015's checks find nothing
	AreaImages = "images" // images by digest, the release's
	AreaRBAC   = "rbac"   // RBAC equals the manifest
)

// Reasons a combination fails.
const (
	ReasonNoCombination  = "no_combination"       // the schema allows no combination of the base values
	ReasonRender         = "render"               // Helm cannot render an allowed combination
	ReasonFinding        = "finding"              // a deployment check found something (subject: check and object)
	ReasonCheckError     = "check_error"          // a deployment check could not run
	ReasonImageTag       = "image_not_by_digest"  // an image named by tag
	ReasonImageUnknown   = "image_not_in_release" // an image of no release component or mirrored copy
	ReasonImageDiffers   = "image_differs"        // an image whose digest is not the release's
	ReasonImageUnlisted  = "image_not_in_package" // an image the package manifest does not list
	ReasonRBACUnexpected = "rbac_not_in_manifest" // an RBAC object the manifest does not list
	ReasonRBACChanged    = "rbac_differs"         // an RBAC object whose hash is not the manifest's
	ReasonRBACMissing    = "rbac_missing"         // a manifest entry the combination switches on is absent
)

var reasonArea = map[string]string{
	ReasonNoCombination: AreaRender, ReasonRender: AreaRender,
	ReasonFinding: AreaChecks, ReasonCheckError: AreaChecks,
	ReasonImageTag: AreaImages, ReasonImageUnknown: AreaImages, ReasonImageDiffers: AreaImages, ReasonImageUnlisted: AreaImages,
	ReasonRBACUnexpected: AreaRBAC, ReasonRBACChanged: AreaRBAC, ReasonRBACMissing: AreaRBAC,
}

// BaseValues are the values every combination starts from: the chart's
// instance values, which no check reads but the schema requires (host
// names, address ranges, buckets). Switches and choices are the gate's.
var BaseValues = map[string]any{
	"database.host":          "db.fair.example",
	"platform.host":          "fair.example",
	"ingress.host":           "ingress.fair.example",
	"ingress.cidr":           "10.40.0.0/16",
	"apiServer.cidr":         "10.40.0.0/16",
	"stores.audit.bucket":    "fair-audit-store",
	"stores.audit.endpoint":  "s3.fair.example:443",
	"stores.audit.region":    "us-gov-west-1",
	"stores.report.bucket":   "fair-report-store",
	"stores.report.endpoint": "s3.fair.example:443",
	"stores.report.region":   "us-gov-west-1",
	"keycloak.host":          "id.fair.example",
}

// Options configure Check.
type Options struct {
	// Chart is the chart: a directory or a packaged .tgz.
	Chart string
	// Manifest is the release manifest the chart must equal.
	Manifest *releasemanifest.Manifest
	// Residue maps a switch (<value>.bundled) to the files of what fairctl
	// applies for it at cluster scope (fleet.BundledResidue).
	Residue map[string][]string
	// PackageImages, when not nil, are the image references the air-gap
	// package holds: every image of every combination must be one.
	PackageImages map[string]bool
	// Base overrides BaseValues (tests); nil: BaseValues.
	Base map[string]any
	// Fixed holds switches or choices at one value instead of enumerating
	// them (a quicker run; the release gate fixes none).
	Fixed map[string]any
	// Workers renders combinations concurrently; 0: the CPUs.
	Workers int
}

// Failure is one refusal, with the combinations it occurs in.
type Failure struct {
	Area    string `json:"area"`
	Reason  string `json:"reason"`
	Subject string `json:"subject"`
	Detail  string `json:"detail,omitempty"`
	// Combinations counts the combinations it occurs in; Example names the
	// first (in enumeration order).
	Combinations int    `json:"combinations"`
	Example      string `json:"example"`
}

func (f Failure) String() string {
	s := f.Reason + " " + f.Subject
	if f.Detail != "" {
		s += ": " + f.Detail
	}
	return fmt.Sprintf("%s (%d combinations, e.g. %s)", s, f.Combinations, f.Example)
}

// Report is the gate's outcome.
type Report struct {
	Chart    string   `json:"chart"`
	Release  string   `json:"release"`
	Switches []string `json:"switches"` // the boolean values enumerated
	Choices  []string `json:"choices"`  // the enumerated values
	// Rendered combinations (allowed by the schema) and those the schema
	// refused.
	Rendered int `json:"rendered"`
	Refused  int `json:"refused"`
	// Objects is the largest render's object count; Checks the catalog's
	// size.
	Objects  int       `json:"objects"`
	Checks   int       `json:"checks"`
	Failures []Failure `json:"failures"`
}

// Failed reports whether any failure is in one of the areas (any area when
// none is named).
func (r *Report) Failed(areas ...string) bool {
	return len(r.In(areas...)) > 0
}

// In returns the failures in the areas (all when none is named).
func (r *Report) In(areas ...string) []Failure {
	var out []Failure
	for _, f := range r.Failures {
		if len(areas) == 0 || slices.Contains(areas, f.Area) {
			out = append(out, f)
		}
	}
	return out
}

// combination is one assignment of the switches and choices.
type combination struct {
	index  int
	name   string
	values map[string]any // full values (base and assignments)
	on     map[string]bool
}

type finding struct{ reason, subject, detail string }

// Check runs the gate. It returns an error only when the chart or its
// inputs cannot be read; refusals are in the report.
func Check(ctx context.Context, o Options) (*Report, error) {
	if o.Manifest == nil {
		return nil, errors.New("chartgate: no release manifest")
	}
	if err := o.Manifest.Validate(); err != nil {
		return nil, err
	}
	ch, err := loader.Load(o.Chart)
	if err != nil {
		return nil, fmt.Errorf("chartgate: %s: %w", o.Chart, err)
	}
	if len(ch.Schema) == 0 {
		return nil, fmt.Errorf("chartgate: %s has no values.schema.json", o.Chart)
	}
	var schema map[string]any
	if err := json.Unmarshal(ch.Schema, &schema); err != nil {
		return nil, fmt.Errorf("chartgate: values.schema.json: %w", err)
	}
	switches, choices := map[string][]any{}, map[string][]any{}
	leaves(schema, "", switches, choices)
	for k, v := range o.Fixed {
		_, sw := switches[k]
		_, chc := choices[k]
		switch {
		case sw:
			switches[k] = []any{v}
		case chc:
			choices[k] = []any{v}
		default:
			return nil, fmt.Errorf("chartgate: %s is neither a switch nor a choice of the chart", k)
		}
	}
	r := &Report{Chart: o.Chart, Release: o.Manifest.Release, Switches: slices.Sorted(maps.Keys(switches)), Choices: slices.Sorted(maps.Keys(choices))}
	if len(r.Switches) == 0 {
		return nil, fmt.Errorf("chartgate: %s has no switches", o.Chart)
	}
	registry, _ := dig(ch.Values, "global", "registry").(string)
	if registry == "" {
		return nil, fmt.Errorf("chartgate: %s has no global.registry default", o.Chart)
	}
	base := o.Base
	if base == nil {
		base = BaseValues
	}
	residue, err := readResidue(o.Residue)
	if err != nil {
		return nil, err
	}
	g := &gate{o: o, registry: registry, residue: residue}
	if err := g.prepare(); err != nil {
		return nil, err
	}
	defer g.close()

	combos := enumerate(base, r.Switches, r.Choices, switches, choices)
	workers := o.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	type result struct {
		c        combination
		refused  bool
		objects  int
		findings []finding
	}
	results := make([]result, len(combos))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var loadErr error
	var once sync.Once
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wch, err := loader.Load(o.Chart) // each worker its own chart: rendering is not shared
			if err != nil {
				once.Do(func() { loadErr = err })
			}
			for i := range jobs {
				if wch == nil || ctx.Err() != nil {
					continue
				}
				c := combos[i]
				refused, n, fs := g.run(ctx, wch, c)
				results[i] = result{c: c, refused: refused, objects: n, findings: fs}
			}
		}()
	}
	for i := range combos {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if loadErr != nil {
		return nil, loadErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.Checks = len(checks.Metas())
	agg := map[finding]*Failure{}
	var order []finding
	for _, res := range results {
		if res.refused {
			r.Refused++
			continue
		}
		r.Rendered++
		r.Objects = max(r.Objects, res.objects)
		for _, f := range res.findings {
			if a, ok := agg[f]; ok {
				a.Combinations++
				continue
			}
			agg[f] = &Failure{Area: reasonArea[f.reason], Reason: f.reason, Subject: f.subject, Detail: f.detail, Combinations: 1, Example: res.c.name}
			order = append(order, f)
		}
	}
	for _, f := range order {
		r.Failures = append(r.Failures, *agg[f])
	}
	if r.Rendered == 0 {
		r.Failures = append(r.Failures, Failure{Area: AreaRender, Reason: ReasonNoCombination, Subject: "values.schema.json",
			Detail: "the schema refuses every combination of the gate's base values", Combinations: len(combos), Example: combos[0].name})
	}
	return r, nil
}

// leaves collects the schema's boolean leaves and enumerated leaves.
func leaves(s map[string]any, path string, switches, choices map[string][]any) {
	props, _ := s["properties"].(map[string]any)
	for k, v := range props {
		sub, _ := v.(map[string]any)
		p := strings.TrimPrefix(path+"."+k, ".")
		switch {
		case sub["type"] == "object":
			leaves(sub, p, switches, choices)
		case sub["type"] == "boolean":
			switches[p] = []any{false, true}
		case sub["enum"] != nil:
			e, _ := sub["enum"].([]any)
			choices[p] = e
		}
	}
}

// enumerate lists every assignment of the switches and choices over base.
func enumerate(base map[string]any, sw, ch []string, switches, choices map[string][]any) []combination {
	keys := append(slices.Clone(ch), sw...)
	domain := func(k string) []any {
		if d, ok := choices[k]; ok {
			return d
		}
		return switches[k]
	}
	var out []combination
	idx := make([]int, len(keys))
	for {
		vals := map[string]any{}
		for p, v := range base {
			setPath(vals, p, v)
		}
		on := map[string]bool{}
		var names []string
		for i, k := range keys {
			v := domain(k)[idx[i]]
			setPath(vals, k, v)
			switch b, isBool := v.(bool); {
			case isBool && b:
				on[k] = true
				names = append(names, "+"+k)
			case !isBool:
				names = append(names, fmt.Sprintf("%s=%v", k, v))
			}
		}
		out = append(out, combination{index: len(out), name: strings.Join(names, " "), values: vals, on: on})
		i := len(keys) - 1
		for ; i >= 0; i-- {
			idx[i]++
			if idx[i] < len(domain(keys[i])) {
				break
			}
			idx[i] = 0
		}
		if i < 0 {
			return out
		}
	}
}

// gate holds what every combination shares.
type gate struct {
	o        Options
	registry string
	residue  map[string][]map[string]any
	manifest *releasemanifest.Manifest // the release manifest (with its mirrors, for the catalog)
	rbac     map[string]releasemanifest.RBACEntry
	mirrored map[string]string // copy reference -> mirror component
	platform *regexp.Regexp
	tlsAddr  string
	lis      net.Listener
}

func (g *gate) prepare() error {
	m := *g.o.Manifest
	g.mirrored = map[string]string{}
	for _, x := range m.Mirrors {
		g.mirrored[x.Image] = x.Component
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("chartgate: the release's images: %w", err)
	}
	g.manifest = &m
	g.rbac = map[string]releasemanifest.RBACEntry{}
	for _, e := range m.RBAC {
		g.rbac[e.Key()] = e
	}
	g.platform = regexp.MustCompile(`^` + regexp.QuoteMeta(g.registry) + `/fair-([a-z0-9][a-z0-9-]*)@(sha256:[0-9a-f]{64})$`)
	var err error
	g.tlsAddr, g.lis, err = serveTLS()
	return err
}

func (g *gate) close() {
	if g.lis != nil {
		_ = g.lis.Close()
	}
}

func readResidue(files map[string][]string) (map[string][]map[string]any, error) {
	out := map[string][]map[string]any{}
	for sw, fs := range files {
		for _, f := range fs {
			b, err := os.ReadFile(f) // #nosec G304 -- the release's own manifests
			if err != nil {
				return nil, err
			}
			docs, err := objreader.DecodeYAML(bytes.NewReader(b))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			out[sw] = append(out[sw], docs...)
		}
	}
	return out, nil
}

// run renders one combination and checks it.
func (g *gate) run(ctx context.Context, ch *chart.Chart, c combination) (refused bool, objects int, out []finding) {
	fail := func(reason, subject, detail string) {
		out = append(out, finding{reason, subject, detail})
	}
	vals, err := chartutil.CoalesceValues(ch, c.values)
	if err != nil {
		fail(ReasonRender, "values", err.Error())
		return false, 0, out
	}
	if err := chartutil.ValidateAgainstSchema(ch, vals); err != nil {
		return true, 0, nil
	}
	rv, err := chartutil.ToRenderValuesWithSchemaValidation(ch, c.values, common.ReleaseOptions{Name: "fair", Namespace: "fair-platform", IsInstall: true}, nil, true)
	if err != nil {
		fail(ReasonRender, "values", err.Error())
		return false, 0, out
	}
	files, err := engine.Render(ch, rv)
	if err != nil {
		fail(ReasonRender, "templates", err.Error())
		return false, 0, out
	}
	var objs []map[string]any
	seen := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if strings.HasSuffix(name, "NOTES.txt") {
			continue
		}
		docs, err := objreader.DecodeYAMLString(files[name])
		if err != nil {
			fail(ReasonRender, name, err.Error())
			continue
		}
		for _, d := range docs {
			k := objreader.Key(d)
			if seen[k] {
				fail(ReasonRender, k, "rendered twice")
				continue
			}
			seen[k] = true
			objs = append(objs, d)
		}
	}
	for sw, docs := range g.residue {
		if c.on[sw] {
			objs = append(objs, docs...)
		}
	}
	for _, f := range g.images(objs) {
		fail(f.reason, f.subject, f.detail)
	}
	for _, f := range g.rbacOf(objs, c) {
		fail(f.reason, f.subject, f.detail)
	}
	for _, f := range g.catalog(ctx, objs) {
		fail(f.reason, f.subject, f.detail)
	}
	return false, len(objs), out
}

// images checks every image an object names.
func (g *gate) images(objs []map[string]any) []finding {
	var out []finding
	for _, o := range objs {
		k := objreader.Key(o)
		for _, ref := range imageRefs(o) {
			subject := k + " " + ref
			switch m := g.platform.FindStringSubmatch(ref); {
			case releasemanifest.Digest(ref) == "":
				out = append(out, finding{ReasonImageTag, subject, "images are named by the release's digest"})
				continue
			case m != nil:
				want, ok := g.o.Manifest.Images[m[1]]
				switch {
				case !ok:
					out = append(out, finding{ReasonImageUnknown, subject, "component " + m[1] + " is not in release " + g.o.Manifest.Release})
					continue
				case want != ref:
					out = append(out, finding{ReasonImageDiffers, subject, "the release manifest names " + want})
					continue
				}
			case g.mirrored[ref] != "":
			default:
				if name := g.mirrorName(ref); name != "" {
					out = append(out, finding{ReasonImageDiffers, subject, "not the release's copy of " + name})
				} else {
					out = append(out, finding{ReasonImageUnknown, subject, "neither a release image nor a mirrored third-party image under " + g.registry})
				}
				continue
			}
			if g.o.PackageImages != nil && !g.o.PackageImages[ref] {
				out = append(out, finding{ReasonImageUnlisted, subject, "package-manifest.json does not list it"})
			}
		}
	}
	return out
}

func (g *gate) mirrorName(ref string) string {
	rest, ok := strings.CutPrefix(ref, g.registry+"/mirror/")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(rest, "@")
	for _, x := range g.o.Manifest.Mirrors {
		if x.Component == name {
			return name
		}
	}
	return ""
}

// imageRefs are the images an object names: every "image" (and a
// CloudNativePG Cluster's "imageName") and every environment value naming
// an image by digest (an operator's image for the pods it makes).
func imageRefs(o map[string]any) []string {
	var out []string
	var walk func(v any, key string)
	walk = func(v any, key string) {
		switch x := v.(type) {
		case map[string]any:
			if n, ok := x["name"].(string); ok && key == "env" {
				if val, ok := x["value"].(string); ok && (strings.Contains(val, "@sha256:") || strings.HasSuffix(n, "_IMAGE") || strings.HasSuffix(n, "IMAGE_NAME")) {
					out = append(out, val)
				}
			}
			for _, k := range slices.Sorted(maps.Keys(x)) {
				if s, ok := x[k].(string); ok && (k == "image" || k == "imageName") {
					out = append(out, s)
					continue
				}
				walk(x[k], k)
			}
		case []any:
			for _, e := range x {
				walk(e, key)
			}
		}
	}
	walk(o, "")
	return out
}

// required reports whether a manifest entry must be in a combination.
func required(e releasemanifest.RBACEntry, c combination) bool {
	return e.Optional == "" || e.Optional == releasemanifest.OptionalHook || c.on[e.Optional]
}

// rbacOf compares the combination's RBAC (hooks and residue included) with
// the manifest.
func (g *gate) rbacOf(objs []map[string]any, c combination) []finding {
	var out []finding
	present := map[string]bool{}
	for _, o := range objs {
		kind, _ := o["kind"].(string)
		if !slices.Contains(releasemanifest.RBACKinds, kind) {
			continue
		}
		raw, err := json.Marshal(o)
		if err != nil {
			out = append(out, finding{ReasonRBACChanged, objreader.Key(o), err.Error()})
			continue
		}
		h, err := releasemanifest.Hash(kind, raw)
		if err != nil {
			out = append(out, finding{ReasonRBACChanged, objreader.Key(o), err.Error()})
			continue
		}
		md, _ := o["metadata"].(map[string]any)
		ns, _ := md["namespace"].(string)
		name, _ := md["name"].(string)
		key := releasemanifest.RBACEntry{Kind: kind, Namespace: ns, Name: name}.Key()
		present[key] = true
		switch e, ok := g.rbac[key]; {
		case !ok:
			out = append(out, finding{ReasonRBACUnexpected, key, "not in the release manifest"})
		case e.SHA256 != h:
			out = append(out, finding{ReasonRBACChanged, key, "its rules, role or subjects differ from the release manifest's"})
		}
	}
	for _, key := range slices.Sorted(maps.Keys(g.rbac)) {
		if e := g.rbac[key]; !present[key] && required(e, c) {
			when := "every installation"
			if e.Optional != "" {
				when = e.Optional
			}
			out = append(out, finding{ReasonRBACMissing, key, "the release manifest lists it for " + when})
		}
	}
	return out
}

// catalog applies the render to the compliant cluster and runs F-015's
// checks over it.
func (g *gate) catalog(ctx context.Context, objs []map[string]any) []finding {
	applied, err := objreader.Applied(objs)
	if err != nil {
		return []finding{{ReasonRender, "apply", err.Error()}}
	}
	set := objreader.New()
	set.NotServed(kube.ExternalSecrets)
	if err := set.AddYAML(bytes.NewReader(CompliantCluster)); err != nil {
		return []finding{{ReasonCheckError, "compliant cluster", err.Error()}}
	}
	for _, o := range applied {
		if _, err := set.Add(o); err != nil {
			return []finding{{ReasonRender, objreader.Key(o), err.Error()}}
		}
	}
	scope := scanner.Scope{ProbeNamespace: ProbeNamespace}
	for _, ns := range set.Namespaces() {
		if ns != ProbeNamespace {
			scope.Namespaces = append(scope.Namespaces, ns)
		}
	}
	cfg := checks.Config{Manifest: g.manifest, Dial: func(ctx context.Context, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil || !strings.HasSuffix(host, ".svc") {
			return nil, fmt.Errorf("no route to %s", addr)
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", g.tlsAddr)
	}}
	var out []finding
	for _, c := range checks.Catalog(cfg) {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		res, err := c.Run(cctx, set, scope)
		cancel()
		if err != nil {
			out = append(out, finding{ReasonCheckError, c.ID(), err.Error()})
			continue
		}
		for _, f := range res.Findings {
			out = append(out, finding{ReasonFinding, c.ID() + " " + f.Subject, f.Severity + " " + f.DetailJSON})
		}
	}
	return out
}

// serveTLS answers every Service of a render with TLS 1.2 or later and a
// certificate valid for a year: the compliant cluster's endpoints (what
// each server's own TLS configuration is, TestBundledManifests and the
// services' tests hold).
func serveTLS() (string, net.Listener, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fair-release-gate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", nil, err
	}
	lis, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		return "", nil, err
	}
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
				_ = c.Close()
			}()
		}
	}()
	return lis.Addr().String(), lis, nil
}

func setPath(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		sub, ok := m[p].(map[string]any)
		if !ok {
			sub = map[string]any{}
			m[p] = sub
		}
		m = sub
	}
	m[parts[len(parts)-1]] = v
}

func dig(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

// Summary is one line per area for the release-check report.
func (r *Report) Summary(area string) string {
	fs := r.In(area)
	if len(fs) == 0 {
		switch area {
		case AreaRender:
			return fmt.Sprintf("%d combinations of %s and %s rendered (%d refused by the schema)", r.Rendered, strings.Join(r.Choices, ", "), strings.Join(r.Switches, ", "), r.Refused)
		case AreaChecks:
			return fmt.Sprintf("%d checks over each of %d renders on the compliant cluster: no finding", r.Checks, r.Rendered)
		case AreaImages:
			return "every image by digest; the release manifest's or its mirrored copy"
		default:
			return "every RBAC object (hooks and fairctl's cluster-scoped objects included) as the release manifest hashes it"
		}
	}
	lines := make([]string, 0, min(len(fs), 5))
	for _, f := range fs[:min(len(fs), 5)] {
		lines = append(lines, f.String())
	}
	if len(fs) > 5 {
		lines = append(lines, fmt.Sprintf("and %d more", len(fs)-5))
	}
	return strings.Join(lines, "; ")
}
