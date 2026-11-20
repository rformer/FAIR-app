package pincheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sha = "3d3c42e5aac5ba805825da76410c181273ba90b1"
const digest = "@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0"

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// F-012 T-01 (F-012-AC-03; design §3.1): every unpinned input is found,
// by file and line; pinned and local ones are not.
func TestPinsEnforced(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		".github/actions/build/action.yml": `runs:
  steps:
    - uses: actions/upload-artifact@v7
`,
		".github/workflows/ci.yml": `jobs:
  a:
    services:
      postgres:
        image: postgres:16
    steps:
      - uses: actions/checkout@v7
      - uses: actions/checkout@` + sha + `
      - uses: actions/checkout@` + sha + ` # v7.0.1
      - uses: ./local-action
      - uses: docker://alpine:3.20
      - run: docker run --rm -v "$PWD:/src" -w /src golang:1.26-bookworm make
      - run: docker run --rm fair-dbtest:latest go test
      - run: npm install
      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
      # - uses: actions/setup-go@v7 (a comment)
  slsa:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.1.0
  slsa-bad:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@main
`,
		"Dockerfile": `ARG BASE=gcr.io/distroless/static-debian12:nonroot` + digest + `
ARG UNPINNED=python:3.12
FROM golang:1.26-bookworm AS build
FROM build AS test
FROM ${BASE} AS run
FROM ${UNPINNED}
FROM ${NOPE}
FROM scratch
`,
		"scripts/e2e/run.sh": `IMAGE=${IMAGE:-quay.io/keycloak/keycloak:26.0.7}
OK_IMAGE=${OK_IMAGE:-busybox:1.36` + digest + `}
docker run -d -p 8099:8099 -u 65532:65532 nats:2.10 -js
kubectl debug pod --image=busybox:1.36 -- sleep 1
`,
		"scripts/e2e/fixture.yaml": "spec:\n  containers:\n    - image: busybox:1.36\n",
		"engine/requirements.lock": "numpy==2.0.0 \\\n    --hash=sha256:" + strings.Repeat("a", 64) + "\nscipy==1.14.0\n",
		"web/package.json":         "{}",
		"mod/go.mod":               "module x\n",
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
		".github/actions/build/action.yml:3: action actions/upload-artifact@v7 is not pinned to a full commit",
		".github/workflows/ci.yml:5: image postgres:16 is not pinned by digest (@sha256:...)",
		".github/workflows/ci.yml:7: action actions/checkout@v7 is not pinned to a full commit",
		".github/workflows/ci.yml:8: action actions/checkout@" + sha + " has no version comment (# vX.Y.Z)",
		".github/workflows/ci.yml:11: docker://alpine:3.20 is not pinned by digest",
		".github/workflows/ci.yml:12: image golang:1.26-bookworm is not pinned by digest (@sha256:...)",
		".github/workflows/ci.yml:14: npm install: use npm ci with the lock file",
		".github/workflows/ci.yml:15: go run of golang.org/x/vuln/cmd/govulncheck@latest: name a version",
		".github/workflows/ci.yml:20: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@main must be referenced by a release tag (vX.Y.Z)",
		"Dockerfile:3: FROM golang:1.26-bookworm is not pinned by digest",
		"Dockerfile:6: FROM python:3.12 is not pinned by digest",
		"Dockerfile:7: FROM ${NOPE}: the variable has no pinned default",
		"engine/requirements.lock:3: requirement scipy==1.14.0 has no --hash",
		"mod/go.mod: go.mod without go.sum",
		"scripts/e2e/fixture.yaml:3: image busybox:1.36 is not pinned by digest (@sha256:...)",
		"scripts/e2e/run.sh:1: image quay.io/keycloak/keycloak:26.0.7 is not pinned by digest (@sha256:...)",
		"scripts/e2e/run.sh:3: image nats:2.10 is not pinned by digest (@sha256:...)",
		"scripts/e2e/run.sh:4: image busybox:1.36 is not pinned by digest (@sha256:...)",
		"web/package.json: package.json without package-lock.json",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("problems\n got:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

// The repository itself is pinned (the CI step runs the command too).
func TestRepositoryPinned(t *testing.T) {
	got, err := Check(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		t.Error(p)
	}
}
