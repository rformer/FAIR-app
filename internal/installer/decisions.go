package installer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DecisionsFormat names the decisions file (docs/formats/fair-install-decisions-v1.md).
const DecisionsFormat = "fair.install-decisions.v1"

// maxDecisions bounds a decisions file.
const maxDecisions = 1 << 20

// Decisions are an install's decisions (design §3.4, AC-14): what the
// interactive prompts would ask, in a file. Credentials are never values,
// only the paths of files that hold them.
type Decisions struct {
	Format       string       `yaml:"format"`
	Operator     string       `yaml:"operator"` // the operator's stated name (events: operator:<name>)
	Mode         string       `yaml:"mode"`     // saas, self-hosted or air-gapped
	Profile      string       `yaml:"profile"`  // a built-in posture profile
	Currency     string       `yaml:"currency"` // ISO 4217
	IDP          IDP          `yaml:"idp"`
	Admin        Admin        `yaml:"admin"`
	Scanner      Scanner      `yaml:"scanner"`
	NodeFIPS     NodeFIPS     `yaml:"node_fips"`
	Attestations Attestations `yaml:"attestations"`
	BreakGlass   BreakGlass   `yaml:"break_glass"`
	Overrides    []Override   `yaml:"overrides"`
	Sizes        Sizes        `yaml:"sizes"`
	Hosts        Hosts        `yaml:"hosts"`
	Registry     string       `yaml:"registry"` // the private registry the images were loaded into (chart global.registry)
	KeyStore     KeyStore     `yaml:"key_store"`
	TLS          TLS          `yaml:"tls"`
	Dependencies Dependencies `yaml:"dependencies"`

	dir string // the file's directory: relative paths resolve there
}

// IDP is the first identity provider.
type IDP struct {
	Kind             string   `yaml:"kind"` // saml, oidc or keycloak (the bundled Keycloak)
	Name             string   `yaml:"name"`
	MetadataFile     string   `yaml:"metadata_file"` // saml: the IDP's metadata
	Issuer           string   `yaml:"issuer"`        // oidc
	ClientID         string   `yaml:"client_id"`     // oidc
	ClientSecretFile string   `yaml:"client_secret_file"`
	Domains          []string `yaml:"domains"` // email domains for home-realm discovery
}

// Admin is the first Platform Admin.
type Admin struct {
	Email   string `yaml:"email"`
	Subject string `yaml:"subject"` // the IDP's subject for them
}

// Scanner is the Kubernetes-access decision (F-015 T-30).
type Scanner struct {
	Access         string `yaml:"access"`          // grant or decline
	ManifestSHA256 string `yaml:"manifest_sha256"` // the permission manifest the administrator accepted (grant)
}

// NodeFIPS is how node FIPS mode is evidenced.
type NodeFIPS struct {
	Evidence string `yaml:"evidence"` // probe or attest
	Reason   string `yaml:"reason"`   // attest
}

// Attestations are statements the installer records as "attested, not
// verified".
type Attestations struct {
	PodSecurity       *Attestation       `yaml:"pod_security"` // cluster-wide pod security admission
	StorageEncryption []ClassAttestation `yaml:"storage_encryption"`
}

// Attestation is a reasoned statement.
type Attestation struct {
	Reason string `yaml:"reason"`
}

// ClassAttestation attests a storage class's encryption.
type ClassAttestation struct {
	Class  string `yaml:"class"`
	Reason string `yaml:"reason"`
}

// BreakGlass is the break-glass decision (F-001 T-34): off, or a reason
// and the holders.
type BreakGlass struct {
	Enabled bool     `yaml:"enabled"`
	Reason  string   `yaml:"reason"`
	Holders []string `yaml:"holders"` // email addresses
}

// Override names a preflight failure to proceed past (design §3.8).
type Override struct {
	Check   string `yaml:"check"`
	Subject string `yaml:"subject"`
	Reason  string `yaml:"reason"`
}

// Sizes are the chart's size values.
type Sizes struct {
	AuditStorageQuota string         `yaml:"audit_storage_quota"` // e.g. 500Gi
	Replicas          map[string]int `yaml:"replicas"`            // per Deployment, 2 to 20
}

// Hosts are the installation's names and address ranges.
type Hosts struct {
	Platform      string `yaml:"platform"`
	Ingress       string `yaml:"ingress"`
	Keycloak      string `yaml:"keycloak"`
	IngressCIDR   string `yaml:"ingress_cidr"`
	APIServerCIDR string `yaml:"api_server_cidr"`
}

// KeyStore is the mode's key store (F-001 T-41).
type KeyStore struct {
	Kind      string `yaml:"kind"` // kubernetes-secrets or openbao
	Address   string `yaml:"address"`
	CAFile    string `yaml:"ca_file"`
	TokenFile string `yaml:"token_file"` // an administrative token for configuring a brought OpenBao
}

// TLS is the internal TLS issuer (design §3.6).
type TLS struct {
	Issuer            string `yaml:"issuer"` // installation-ca (default), cert-manager or files
	CertManagerIssuer string `yaml:"cert_manager_issuer"`
	CAFile            string `yaml:"ca_file"`
	CertFile          string `yaml:"cert_file"`
	KeyFile           string `yaml:"key_file"`
}

// Dependencies are bundled (the chart's switches) or brought, with their
// endpoints and credential files.
type Dependencies struct {
	Postgres    Postgres    `yaml:"postgres"`
	NATS        NATS        `yaml:"nats"`
	ObjectStore ObjectStore `yaml:"object_store"`
	Keycloak    Bundled     `yaml:"keycloak"`
	OpenBao     Bundled     `yaml:"openbao"`
	Collector   Collector   `yaml:"collector"`
}

// Bundled is a dependency with no brought form here.
type Bundled struct {
	Bundled bool `yaml:"bundled"`
}

// Postgres is the database.
type Postgres struct {
	Bundled           bool   `yaml:"bundled"`
	Host              string `yaml:"host"`
	Port              int    `yaml:"port"`
	Database          string `yaml:"database"`
	AdminUser         string `yaml:"admin_user"`
	AdminPasswordFile string `yaml:"admin_password_file"`
	CAFile            string `yaml:"ca_file"`
}

// NATS is the message bus.
type NATS struct {
	Bundled         bool   `yaml:"bundled"`
	URL             string `yaml:"url"`
	CAFile          string `yaml:"ca_file"`
	CredentialsFile string `yaml:"credentials_file"`
}

// ObjectStore is the S3 store for the audit trail and reports.
type ObjectStore struct {
	Bundled       bool   `yaml:"bundled"`
	Endpoint      string `yaml:"endpoint"`
	Region        string `yaml:"region"`
	AuditBucket   string `yaml:"audit_bucket"`
	ReportBucket  string `yaml:"report_bucket"`
	WORMBucket    string `yaml:"worm_bucket"`
	AccessKeyFile string `yaml:"access_key_file"`
	SecretKeyFile string `yaml:"secret_key_file"`
	CAFile        string `yaml:"ca_file"`
	CreateBuckets bool   `yaml:"create_buckets"`
}

// Collector is the OpenTelemetry Collector.
type Collector struct {
	Bundled  bool   `yaml:"bundled"`
	Endpoint string `yaml:"endpoint"`
}

// Problem is one refusal, by field.
type Problem struct {
	Field   string `json:"field"`
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
}

func (p Problem) String() string {
	if p.Line > 0 {
		return fmt.Sprintf("line %d: %s: %s", p.Line, p.Field, p.Message)
	}
	return p.Field + ": " + p.Message
}

// DecisionsError lists every problem with a decisions file. No problem
// repeats a value that looked secret.
type DecisionsError struct {
	Secret   bool // the file was refused for a secret-looking value
	Problems []Problem
}

func (e *DecisionsError) Error() string {
	parts := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		parts[i] = p.String()
	}
	return "decisions: " + strings.Join(parts, "; ")
}

// LoadDecisions reads a decisions file; relative paths in it resolve
// against its directory.
func LoadDecisions(path string) (*Decisions, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's decisions file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxDecisions+1))
	if err != nil {
		return nil, err
	}
	d, err := ParseDecisions(b)
	if err != nil {
		return nil, err
	}
	d.dir = filepath.Dir(path)
	return d, nil
}

// ParseDecisions parses and checks a decisions file: secret-looking values
// anywhere refuse the whole file before it is decoded (credentials are file
// paths); then the strict decoding (unknown fields refused) and every field.
func ParseDecisions(b []byte) (*Decisions, error) {
	if len(b) > maxDecisions {
		return nil, &DecisionsError{Problems: []Problem{{Field: "file", Message: "larger than 1 MiB"}}}
	}
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, &DecisionsError{Problems: []Problem{{Field: "file", Message: yamlMessage(err)}}}
	}
	if probs := secretProblems(&root, ""); len(probs) > 0 {
		secret := slices.ContainsFunc(probs, func(p Problem) bool { return p.Message != aliasMessage })
		return nil, &DecisionsError{Secret: secret, Problems: probs}
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var d Decisions
	if err := dec.Decode(&d); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, &DecisionsError{Problems: []Problem{{Field: "file", Message: "empty"}}}
		}
		return nil, &DecisionsError{Problems: []Problem{{Field: "file", Message: yamlMessage(err)}}}
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, &DecisionsError{Problems: []Problem{{Field: "file", Message: "more than one YAML document"}}}
	}
	if probs := d.Check(); len(probs) > 0 {
		return nil, &DecisionsError{Problems: probs}
	}
	return &d, nil
}

// yamlMessage is a YAML error without the document's text (yaml.v3 quotes
// values in some messages, which might be secret: the scan above runs
// first, but a malformed file is not scanned).
func yamlMessage(err error) string {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		var out []string
		for _, e := range te.Errors {
			out = append(out, redactQuoted(e))
		}
		return strings.Join(out, "; ")
	}
	return redactQuoted(err.Error())
}

var quoted = regexp.MustCompile("`[^`]*`|\"[^\"]*\"")

func redactQuoted(s string) string {
	return quoted.ReplaceAllStringFunc(s, func(q string) string {
		if LooksSecret(q) {
			return "(value withheld)"
		}
		return q
	})
}

const aliasMessage = "aliases are not allowed"

// secretProblems walks the document: any scalar that looks secret, any key
// naming a secret that is not a *_file path, and any alias (strict files
// have none) is a problem. Values are never repeated.
func secretProblems(n *yaml.Node, path string) []Problem {
	var out []Problem
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for i, c := range n.Content {
			p := path
			if n.Kind == yaml.SequenceNode {
				p = fmt.Sprintf("%s[%d]", path, i)
			}
			out = append(out, secretProblems(c, p)...)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			p := k.Value
			if path != "" {
				p = path + "." + k.Value
			}
			if LooksSecret(k.Value) {
				out = append(out, Problem{Field: path, Line: k.Line, Message: "a key looks like a secret"})
				continue
			}
			if secretKey(k.Value) && v.Kind == yaml.ScalarNode && v.Value != "" {
				out = append(out, Problem{Field: p, Line: v.Line, Message: "names a secret: give the path of a file that holds it (a *_file field), never the value"})
				continue
			}
			out = append(out, secretProblems(v, p)...)
		}
	case yaml.ScalarNode:
		if LooksSecret(n.Value) {
			out = append(out, Problem{Field: path, Line: n.Line, Message: "the value looks like a secret (a key, token or password): credentials are given as file paths; the file is refused before anything runs"})
		}
	case yaml.AliasNode:
		out = append(out, Problem{Field: path, Line: n.Line, Message: aliasMessage})
	}
	return out
}

var (
	profileRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	currencyRE = regexp.MustCompile(`^[A-Z]{3}$`)
	emailRE    = regexp.MustCompile(`^[^@\s]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
	hostRE     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	domainRE   = hostRE
	hexRE      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	checkRE    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	nameRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`)
	quantityRE = regexp.MustCompile(`^[1-9][0-9]{0,5}(Gi|Ti)$`)
	registryRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)*$`)
	bucketRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

// Modes are the deployment modes (ADR-005).
var Modes = []string{"saas", "self-hosted", "air-gapped"}

// Check returns every problem with the decisions' fields.
func (d *Decisions) Check() []Problem {
	var ps []Problem
	bad := func(field, msg string) { ps = append(ps, Problem{Field: field, Message: msg}) }
	need := func(field, v string) bool {
		if strings.TrimSpace(v) == "" {
			bad(field, "required")
			return false
		}
		return true
	}
	match := func(field, v string, re *regexp.Regexp, what string) {
		if need(field, v) && !re.MatchString(v) {
			bad(field, "is not "+what)
		}
	}
	file := func(field, v string, required bool) {
		if v == "" {
			if required {
				bad(field, "required (the path of a file)")
			}
			return
		}
		if !isPath(v) {
			bad(field, "is not a file path")
		}
	}
	reason := func(field, v string) {
		if need(field, v) && len(v) > 1000 {
			bad(field, "longer than 1,000 characters")
		}
	}
	https := func(field, v string, required bool) {
		if v == "" {
			if required {
				bad(field, "required")
			}
			return
		}
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			bad(field, "is not an https URL")
		}
	}
	none := func(field string, vs ...string) {
		for _, v := range vs {
			if v != "" {
				bad(field, "set for a bundled dependency (fairctl provisions it)")
				return
			}
		}
	}

	if d.Format != DecisionsFormat {
		bad("format", "must be "+DecisionsFormat)
	}
	if _, err := OperatorActor(d.Operator); err != nil {
		bad("operator", "1 to 200 printable characters, required")
	}
	if !slices.Contains(Modes, d.Mode) {
		bad("mode", "must be saas, self-hosted or air-gapped")
	}
	match("profile", d.Profile, profileRE, "a profile name")
	match("currency", d.Currency, currencyRE, "an ISO 4217 code (three capital letters)")

	switch d.IDP.Kind {
	case "saml":
		file("idp.metadata_file", d.IDP.MetadataFile, true)
		if d.IDP.Issuer != "" || d.IDP.ClientID != "" || d.IDP.ClientSecretFile != "" {
			bad("idp", "issuer, client_id and client_secret_file are OIDC's")
		}
	case "oidc":
		https("idp.issuer", d.IDP.Issuer, true)
		need("idp.client_id", d.IDP.ClientID)
		file("idp.client_secret_file", d.IDP.ClientSecretFile, true)
		if d.IDP.MetadataFile != "" {
			bad("idp.metadata_file", "is SAML's")
		}
	case "keycloak":
		if !d.Dependencies.Keycloak.Bundled {
			bad("idp.kind", "keycloak is the bundled Keycloak: set dependencies.keycloak.bundled")
		}
	default:
		bad("idp.kind", "must be saml, oidc or keycloak")
	}
	need("idp.name", d.IDP.Name)
	if len(d.IDP.Domains) == 0 {
		bad("idp.domains", "at least one email domain")
	}
	for i, dom := range d.IDP.Domains {
		if !domainRE.MatchString(dom) {
			bad(fmt.Sprintf("idp.domains[%d]", i), "is not a domain name (lower case)")
		}
	}
	match("admin.email", d.Admin.Email, emailRE, "an email address")
	need("admin.subject", d.Admin.Subject)

	switch d.Scanner.Access {
	case "grant":
		match("scanner.manifest_sha256", d.Scanner.ManifestSHA256, hexRE, "the permission manifest's SHA-256 (64 hex digits)")
	case "decline":
		if d.Scanner.ManifestSHA256 != "" {
			bad("scanner.manifest_sha256", "only with access grant")
		}
	default:
		bad("scanner.access", "must be grant or decline")
	}
	switch d.NodeFIPS.Evidence {
	case "probe":
		if d.NodeFIPS.Reason != "" {
			bad("node_fips.reason", "only with evidence attest")
		}
	case "attest":
		reason("node_fips.reason", d.NodeFIPS.Reason)
	default:
		bad("node_fips.evidence", "must be probe or attest")
	}
	if a := d.Attestations.PodSecurity; a != nil {
		reason("attestations.pod_security.reason", a.Reason)
	}
	classes := map[string]bool{}
	for i, c := range d.Attestations.StorageEncryption {
		f := fmt.Sprintf("attestations.storage_encryption[%d]", i)
		match(f+".class", c.Class, nameRE, "a storage class name")
		if classes[c.Class] {
			bad(f+".class", "attested twice")
		}
		classes[c.Class] = true
		reason(f+".reason", c.Reason)
	}
	if d.BreakGlass.Enabled {
		reason("break_glass.reason", d.BreakGlass.Reason)
		if len(d.BreakGlass.Holders) == 0 {
			bad("break_glass.holders", "at least one holder")
		}
		for i, h := range d.BreakGlass.Holders {
			if !emailRE.MatchString(h) {
				bad(fmt.Sprintf("break_glass.holders[%d]", i), "is not an email address")
			}
		}
	} else if d.BreakGlass.Reason != "" || len(d.BreakGlass.Holders) > 0 {
		bad("break_glass", "reason and holders only when enabled")
	}
	seen := map[string]bool{}
	for i, o := range d.Overrides {
		f := fmt.Sprintf("overrides[%d]", i)
		match(f+".check", o.Check, checkRE, "a check identifier")
		need(f+".subject", o.Subject)
		reason(f+".reason", o.Reason)
		if k := o.Check + "\x00" + o.Subject; seen[k] {
			bad(f, "the same check and subject twice")
		} else {
			seen[k] = true
		}
	}
	if d.Mode == "saas" && len(d.Overrides) > 0 {
		bad("overrides", "SaaS allows no override (design §3.7)")
	}

	if q := d.Sizes.AuditStorageQuota; q != "" && !quantityRE.MatchString(q) {
		bad("sizes.audit_storage_quota", "is not a size in Gi or Ti")
	}
	for name, n := range d.Sizes.Replicas {
		if !nameRE.MatchString(name) || n < 2 || n > 20 {
			bad("sizes.replicas."+name, "a Deployment name with 2 to 20 replicas")
		}
	}
	match("hosts.platform", d.Hosts.Platform, hostRE, "a host name")
	if d.Hosts.Ingress != "" && !hostRE.MatchString(d.Hosts.Ingress) {
		bad("hosts.ingress", "is not a host name")
	}
	if d.Dependencies.Keycloak.Bundled {
		match("hosts.keycloak", d.Hosts.Keycloak, hostRE, "a host name (the bundled Keycloak's origin)")
		if !d.Dependencies.Postgres.Bundled {
			bad("dependencies.keycloak.bundled", "needs the bundled PostgreSQL (dependencies.postgres.bundled)")
		}
	} else if d.Hosts.Keycloak != "" {
		bad("hosts.keycloak", "only with the bundled Keycloak")
	}
	for f, v := range map[string]string{"hosts.ingress_cidr": d.Hosts.IngressCIDR, "hosts.api_server_cidr": d.Hosts.APIServerCIDR} {
		if v != "" && !ipv4CIDR(v) {
			bad(f, "is not an IPv4 range from /8 to /32")
		}
	}
	if d.Registry != "" && !registryRE.MatchString(d.Registry) {
		bad("registry", "is not a registry host and path")
	}

	switch d.KeyStore.Kind {
	case "kubernetes-secrets":
		if d.KeyStore.Address != "" || d.KeyStore.CAFile != "" || d.KeyStore.TokenFile != "" {
			bad("key_store", "address, ca_file and token_file are OpenBao's")
		}
		if d.Dependencies.OpenBao.Bundled {
			bad("dependencies.openbao.bundled", "the bundled OpenBao is the key store: key_store.kind openbao")
		}
	case "openbao":
		if d.Dependencies.OpenBao.Bundled {
			none("key_store", d.KeyStore.Address, d.KeyStore.CAFile, d.KeyStore.TokenFile)
		} else {
			https("key_store.address", d.KeyStore.Address, true)
			file("key_store.ca_file", d.KeyStore.CAFile, true)
			file("key_store.token_file", d.KeyStore.TokenFile, true)
		}
	default:
		bad("key_store.kind", "must be kubernetes-secrets or openbao")
	}
	switch d.TLS.Issuer {
	case "", "installation-ca":
		if d.TLS.CertManagerIssuer != "" || d.TLS.CAFile != "" || d.TLS.CertFile != "" || d.TLS.KeyFile != "" {
			bad("tls", "the installation CA takes no other field")
		}
	case "cert-manager":
		match("tls.cert_manager_issuer", d.TLS.CertManagerIssuer, nameRE, "an issuer name")
	case "files":
		file("tls.ca_file", d.TLS.CAFile, true)
		file("tls.cert_file", d.TLS.CertFile, true)
		file("tls.key_file", d.TLS.KeyFile, true)
	default:
		bad("tls.issuer", "must be installation-ca, cert-manager or files")
	}

	pg := d.Dependencies.Postgres
	if pg.Bundled {
		none("dependencies.postgres", pg.Host, pg.Database, pg.AdminUser, pg.AdminPasswordFile, pg.CAFile)
		if pg.Port != 0 {
			bad("dependencies.postgres.port", "set for a bundled dependency (fairctl provisions it)")
		}
	} else {
		if need("dependencies.postgres.host", pg.Host) && !hostRE.MatchString(pg.Host) && net.ParseIP(pg.Host) == nil {
			bad("dependencies.postgres.host", "is not a host name or address")
		}
		if pg.Port < 0 || pg.Port > 65535 {
			bad("dependencies.postgres.port", "is not a port")
		}
		need("dependencies.postgres.database", pg.Database)
		need("dependencies.postgres.admin_user", pg.AdminUser)
		file("dependencies.postgres.admin_password_file", pg.AdminPasswordFile, true)
		file("dependencies.postgres.ca_file", pg.CAFile, true)
	}
	nt := d.Dependencies.NATS
	if nt.Bundled {
		none("dependencies.nats", nt.URL, nt.CAFile, nt.CredentialsFile)
	} else {
		if u, err := url.Parse(nt.URL); nt.URL == "" || err != nil || (u.Scheme != "tls" && u.Scheme != "nats") || u.Host == "" || u.User != nil {
			bad("dependencies.nats.url", "a tls:// or nats:// URL (TLS is required either way), required")
		}
		file("dependencies.nats.ca_file", nt.CAFile, true)
		file("dependencies.nats.credentials_file", nt.CredentialsFile, true)
	}
	st := d.Dependencies.ObjectStore
	if st.Bundled {
		none("dependencies.object_store", st.Endpoint, st.Region, st.AccessKeyFile, st.SecretKeyFile, st.CAFile)
	} else {
		https("dependencies.object_store.endpoint", st.Endpoint, true)
		file("dependencies.object_store.access_key_file", st.AccessKeyFile, true)
		file("dependencies.object_store.secret_key_file", st.SecretKeyFile, true)
		file("dependencies.object_store.ca_file", st.CAFile, false)
	}
	for f, v := range map[string]string{"dependencies.object_store.audit_bucket": st.AuditBucket, "dependencies.object_store.report_bucket": st.ReportBucket} {
		match(f, v, bucketRE, "a bucket name")
	}
	if st.WORMBucket != "" && !bucketRE.MatchString(st.WORMBucket) {
		bad("dependencies.object_store.worm_bucket", "is not a bucket name")
	}
	if c := d.Dependencies.Collector; c.Bundled {
		none("dependencies.collector", c.Endpoint)
	} else {
		https("dependencies.collector.endpoint", c.Endpoint, false)
	}
	if d.Mode == "air-gapped" {
		for f, v := range map[string]string{"idp.issuer": d.IDP.Issuer, "dependencies.object_store.endpoint": st.Endpoint, "dependencies.collector.endpoint": d.Dependencies.Collector.Endpoint} {
			if v != "" && publicHost(v) {
				bad(f, "air-gapped: must be inside the boundary (a private address or a name; preflight checks names)")
			}
		}
	}
	slices.SortStableFunc(ps, func(a, b Problem) int { return strings.Compare(a.Field, b.Field) })
	return ps
}

// isPath reports whether s can be a file path: printable, one line, not a
// PEM block, at most 4,096 bytes.
func isPath(s string) bool {
	if len(s) > 4096 || strings.TrimSpace(s) != s || strings.HasPrefix(s, "-----") {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func ipv4CIDR(s string) bool {
	ip, n, err := net.ParseCIDR(s)
	if err != nil || ip.To4() == nil {
		return false
	}
	ones, _ := n.Mask.Size()
	return ones >= 8 && ones <= 32
}

// publicHost reports whether a URL's host is a public IP address.
func publicHost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// Path resolves a path from the decisions file against its directory.
func (d *Decisions) Path(p string) string {
	if p == "" || filepath.IsAbs(p) || d.dir == "" {
		return p
	}
	return filepath.Join(d.dir, p)
}
