package pincheck

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

const (
	tarSum = "034a2a7535d67ae6f28962976a530dad1bd912dd2d9af05a3990f3b7e674008e"
	commit = "2a9066eb57ff4aa50d8e6a979bdfbd6a8b9db251"
	base   = "quay.io/keycloak/keycloak:26.8.2" + digest
)

// F-014 T-07 (F-014-AC-17; design §3.3, D-OQ3): every upstream input of a
// bundled image is pinned in deploy/bundled/sources.json, and the file and
// the Dockerfile agree: an ADD without a checksum, an ADD the file does not
// pin or pins with another checksum, an entry no ADD uses, a base image no
// FROM uses, and malformed entries are all found.
func TestBundledSourcesTiedToDockerfile(t *testing.T) {
	root := t.TempDir()
	sources := `{"format": "fair.bundled-sources.v1", "checked": "2026-11-26", "sources": [
  {"name": "nats-server", "component": "nats", "kind": "source", "version": "2.15.3", "repository": "https://github.com/nats-io/nats-server",
   "tag": "v2.15.3", "commit": "` + commit + `", "url": "https://example.test/nats.tar.gz", "sha256": "` + tarSum + `", "license": "Apache-2.0", "fips": "Go module"},
  {"name": "jar", "component": "kc", "kind": "artifact", "version": "1", "url": "https://example.test/a.jar", "sha256": "` + tarSum + `", "license": "MIT", "fips": "x"},
  {"name": "unused", "component": "kc", "kind": "artifact", "version": "1", "url": "https://example.test/unused.jar", "sha256": "` + tarSum + `", "license": "MIT", "fips": "x"},
  {"name": "keycloak", "component": "kc", "kind": "base-image", "version": "26.8.2", "repository": "https://github.com/keycloak/keycloak",
   "tag": "26.8.2", "commit": "` + commit + `", "image": "` + base + `", "license": "Apache-2.0", "fips": "x"},
  {"name": "other-base", "component": "kc", "kind": "base-image", "version": "1", "repository": "https://example.test/r",
   "tag": "1", "commit": "` + commit + `", "image": "example.test/other:1` + digest + `", "license": "Apache-2.0", "fips": "x"},
  {"name": "operator", "component": "op", "kind": "mirror", "version": "1", "repository": "https://example.test/r", "tag": "v1", "commit": "` + commit + `",
   "image": "example.test/op:1` + digest + `", "certificate_identity": "^https://.*", "certificate_oidc_issuer": "https://token.actions.githubusercontent.com", "license": "Apache-2.0", "fips": "x"},
  {"name": "short", "component": "nats", "kind": "source", "version": "1", "repository": "https://example.test/r", "tag": "v1", "commit": "2a9066e",
   "url": "http://example.test/short.tar.gz", "sha256": "` + tarSum + `", "license": "MIT", "fips": "x"}
]}`
	write(t, root, map[string]string{
		"deploy/bundled/sources.json": sources,
		"Dockerfile": `FROM golang:1.26.11-bookworm` + digest + ` AS b
ADD --checksum=sha256:` + tarSum + ` https://example.test/nats.tar.gz /tmp/src.tar.gz
ADD --chmod=0644 --checksum=sha256:` + tarSum + ` https://example.test/a.jar /p/
ADD https://example.test/nochecksum.tar.gz /tmp/
ADD --checksum=sha256:` + strings.Repeat("b", 64) + ` https://example.test/nats.tar.gz /tmp/x
ADD --checksum=sha256:` + tarSum + ` https://example.test/elsewhere.tar.gz /tmp/y
ADD --checksum=sha256:` + tarSum + ` http://example.test/short.tar.gz /tmp/z
ADD local.txt /tmp/
FROM ` + base + ` AS kc
`,
	})
	got, err := Check(root)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, p := range got {
		lines = append(lines, p.String())
	}
	want := []string{
		"Dockerfile:4: ADD https://example.test/nochecksum.tar.gz has no --checksum=sha256:...",
		"Dockerfile:5: ADD https://example.test/nats.tar.gz: checksum " + strings.Repeat("b", 64) + ", deploy/bundled/sources.json pins " + tarSum,
		"Dockerfile:6: ADD https://example.test/elsewhere.tar.gz is not pinned in deploy/bundled/sources.json",
		"deploy/bundled/sources.json: source 5 (operator): needs its publisher's exact certificate identity and issuer",
		"deploy/bundled/sources.json: source 6 (short): needs its repository, tag and the tag's full commit",
		"deploy/bundled/sources.json: source 6 (short): needs an https URL and its SHA-256",
		"deploy/bundled/sources.json: source unused is pinned but no Dockerfile ADDs https://example.test/unused.jar",
		"deploy/bundled/sources.json: base image example.test/other:1" + digest + " is pinned but no Dockerfile builds FROM it",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("problems\n got:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

// Without the file, an ADD of a URL is unpinned.
func TestBundledAddNeedsSources(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"Dockerfile": "ADD --checksum=sha256:" + tarSum + " https://example.test/a.tar.gz /a\n"})
	got, err := Check(root)
	if err != nil || len(got) != 1 || !strings.Contains(got[0].Message, "is not pinned in deploy/bundled/sources.json") {
		t.Fatalf("%v %v", got, err)
	}
}

// The repository's own file: the PostgreSQL image's SPDX document names
// the FIPS provider at its validated version, as OpenSSL for matching.
func TestBundledSPDX(t *testing.T) {
	s, problems, err := LoadBundledSources(filepath.Join("..", "..", filepath.FromSlash(BundledSourcesFile)))
	if err != nil || len(problems) > 0 {
		t.Fatal(err, problems)
	}
	b, err := s.SPDX("postgres")
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"versionInfo"`
			Refs    []struct {
				Locator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range d.Packages {
		if p.Name == "openssl-fips-provider" {
			found = p.Version == "3.1.2" && len(p.Refs) == 2 && strings.HasPrefix(p.Refs[1].Locator, "cpe:2.3:a:openssl:openssl:3.1.2:")
		}
	}
	if !found || len(d.Packages) != 3 {
		t.Errorf("%s", b)
	}
	if again, _ := s.SPDX("postgres"); string(again) != string(b) {
		t.Error("not deterministic")
	}
	if _, err := s.SPDX("cloudnative-pg"); err == nil {
		t.Error("a mirrored image has no sources to list")
	}
}
