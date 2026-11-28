package installer

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Bundled dependencies' in-cluster addresses (deploy/bundled; fleet.Bundled).
const (
	BundledDatabaseHost    = "fair-db-rw.fair-data.svc"
	BundledObjectStoreAddr = "versitygw.fair-objects.svc:443"
)

var camelRE = regexp.MustCompile(`-([a-z0-9])`)

// ChartValues are the fair-platform chart's values for the decisions
// (internal/fleet's chart values; the chart's closed schema refuses
// anything else): what preflight renders (T-13) and install installs
// (T-18). Decisions carry no secret, so neither do the values.
func ChartValues(d *Decisions) map[string]any {
	v := map[string]any{}
	set := func(path string, val any) {
		m := v
		parts := strings.Split(path, ".")
		for _, p := range parts[:len(parts)-1] {
			n, ok := m[p].(map[string]any)
			if !ok {
				n = map[string]any{}
				m[p] = n
			}
			m = n
		}
		m[parts[len(parts)-1]] = val
	}
	if d.Registry != "" {
		set("global.registry", d.Registry)
	}
	if d.Mode == "self-hosted" || d.Mode == "air-gapped" {
		set("mode", d.Mode)
	}
	if d.KeyStore.Kind != "" {
		set("keyStore.kind", d.KeyStore.Kind)
	}
	dep := d.Dependencies
	if dep.Postgres.Bundled {
		set("database.host", BundledDatabaseHost)
	} else {
		set("database.host", dep.Postgres.Host)
	}
	set("platform.host", d.Hosts.Platform)
	ingress := d.Hosts.Ingress
	if ingress == "" {
		ingress = d.Hosts.Platform
	}
	set("ingress.host", ingress)
	set("ingress.cidr", d.Hosts.IngressCIDR)
	set("apiServer.cidr", d.Hosts.APIServerCIDR)
	st := dep.ObjectStore
	endpoint := BundledObjectStoreAddr
	if !st.Bundled {
		endpoint = hostPort(st.Endpoint)
	}
	for name, bucket := range map[string]string{"audit": st.AuditBucket, "report": st.ReportBucket} {
		set("stores."+name+".bucket", bucket)
		set("stores."+name+".endpoint", endpoint)
		if st.Region != "" {
			set("stores."+name+".region", st.Region)
		}
	}
	if q := d.Sizes.AuditStorageQuota; q != "" {
		set("audit.storageQuota", q+"B") // 500Gi -> 500GiB
	}
	for name, n := range d.Sizes.Replicas {
		set("replicas."+camelRE.ReplaceAllStringFunc(name, func(s string) string { return strings.ToUpper(s[1:]) }), n)
	}
	set("scanner.enabled", d.Scanner.Access == "grant")
	set("fipsProbe.enabled", d.NodeFIPS.Evidence == "probe")
	set("postgres.bundled", dep.Postgres.Bundled)
	set("nats.bundled", dep.NATS.Bundled)
	set("objectStore.bundled", st.Bundled)
	set("keycloak.bundled", dep.Keycloak.Bundled)
	set("openbao.bundled", dep.OpenBao.Bundled)
	set("collector.bundled", dep.Collector.Bundled)
	if dep.Keycloak.Bundled {
		set("keycloak.host", d.Hosts.Keycloak)
	}
	return v
}

// hostPort is an https URL's host:port (443 by default).
func hostPort(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), "443")
}
