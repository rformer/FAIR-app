package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/rformer/fair-app/internal/scanner/kube"
)

// The permission manifest (F-015 T-30, AC-39): every Kubernetes permission
// and host access the deployment scanner and fips-probe need, each with its
// purpose. The installer shows it for consent (F-014); its digest records
// what was consented to, so a release that changes it asks again. It is
// generated from scanner.Access (deploy/k8s/permission-manifest.json, kept
// equal by test) and the RBAC in deploy/k8s must grant exactly it.

// PermissionManifestFormat identifies the format.
const PermissionManifestFormat = "fair-scanner-permission-manifest/v1"

// Permission is one granted read.
type Permission struct {
	Scope     string   `json:"scope"` // cluster, platform namespaces, fips-probe namespace
	APIGroup  string   `json:"api_group"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
	Purpose   string   `json:"purpose"`
}

// OtherAccess is non-API access, disclosed with the permissions.
type OtherAccess struct {
	Component string `json:"component"`
	What      string `json:"what"`
	Purpose   string `json:"purpose"`
}

// PermissionManifest is what the installer shows.
type PermissionManifest struct {
	Format      string        `json:"format"`
	Summary     string        `json:"summary"`
	Permissions []Permission  `json:"permissions"`
	Other       []OtherAccess `json:"other_access"`
	NeverGrants []string      `json:"never_grants"`
}

var purposes = map[string]string{
	"namespaces":                      "Pod security admission level of the platform namespaces (labels only)",
	"nodes":                           "FIPS mode attestation labels on nodes",
	"storageclasses":                  "Whether the storage classes of platform volumes encrypt at rest",
	"clusterroles":                    "Detect changes to the platform's cluster-level RBAC",
	"clusterrolebindings":             "Detect cluster-level grants to platform service accounts",
	"validatingadmissionpolicies":     "Presence of an image signature verification policy (metadata)",
	"validatingwebhookconfigurations": "Presence of an image signature verification webhook (metadata)",
	"pods":                            "Workload hardening, running image digests, secret references (never secret values)",
	"deployments":                     "Platform workload inventory",
	"statefulsets":                    "Platform workload inventory",
	"daemonsets":                      "Platform workload inventory",
	"services":                        "TLS endpoints to check (handshake only)",
	"networkpolicies":                 "Default-deny and per-service NetworkPolicies",
	"serviceaccounts":                 "Subjects of the platform's RBAC",
	"roles":                           "Detect changes to the platform's namespace RBAC",
	"rolebindings":                    "Detect changes to the platform's namespace RBAC",
	"persistentvolumeclaims":          "Storage classes used by platform volumes (no data access)",
	"externalsecrets":                 "Whether secrets come from the secrets store (if External Secrets is installed)",
}

// Manifest returns the permission manifest.
func Manifest() (PermissionManifest, error) {
	m := PermissionManifest{Format: PermissionManifestFormat,
		Summary:     "Read-only access for deployment drift detection: get, list and watch on the resources below, never Secrets, never any write.",
		NeverGrants: []string{"secrets", "create", "update", "patch", "delete", "pods/exec", "pods/log", "serviceaccounts/token", "impersonate", "escalate", "bind"}}
	add := func(scope string, rs []kube.Resource, probe bool) error {
		for _, r := range rs {
			purpose := purposes[r.Plural]
			if purpose == "" {
				return fmt.Errorf("permission manifest: no purpose for %s", r)
			}
			if probe && r.Plural == "pods" {
				purpose = "fips-probe readiness per node (FIPS mode verified)"
			}
			i := slices.IndexFunc(m.Permissions, func(p Permission) bool {
				return p.Scope == scope && p.APIGroup == r.Group && p.Purpose == purpose
			})
			if i < 0 {
				m.Permissions = append(m.Permissions, Permission{Scope: scope, APIGroup: r.Group, Verbs: []string{"get", "list", "watch"}, Purpose: purpose})
				i = len(m.Permissions) - 1
			}
			m.Permissions[i].Resources = append(m.Permissions[i].Resources, r.Plural)
		}
		return nil
	}
	if err := add("cluster", Access.Cluster, false); err != nil {
		return m, err
	}
	if err := add("platform namespaces", Access.Namespaced, false); err != nil {
		return m, err
	}
	if err := add("fips-probe namespace", Access.ProbeNamespaced, true); err != nil {
		return m, err
	}
	m.Other = []OtherAccess{
		{Component: "posture-scanner", What: "Network: the Kubernetes API server, the posture service (mTLS), platform pods' TLS ports and the ingress (TLS handshake only), DNS",
			Purpose: "Read the cluster, report findings, check TLS versions and certificates"},
		{Component: "fips-probe", What: "On every node, one host file read-only: /proc/sys/crypto/fips_enabled; no API access, no network",
			Purpose: "Verify the node kernel runs in FIPS mode (optional; nodes may be attested instead)"},
	}
	return m, nil
}

// Encode returns the manifest's canonical JSON.
func (m PermissionManifest) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Digest is the SHA-256 of the canonical JSON: what consent refers to.
func (m PermissionManifest) Digest() (string, error) {
	b, err := m.Encode()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
