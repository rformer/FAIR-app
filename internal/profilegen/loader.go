// Package profilegen resolves OSCAL profiles into catalogs at build time
// (F-015 T-02; design §4, D-OQ3). It implements the subset of NIST's OSCAL
// profile resolution that the platform's sources use: imports (relative
// paths, URLs and back-matter references), include-all and
// include/exclude-controls (with-ids, matching, with-child-controls), as-is
// and flat merge, set-parameters, and alters (adds and removes by id).
//
// Resolution never touches the network: every import must resolve to a file
// pinned in third_party/oscal/MANIFEST.json.
package profilegen

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Loader returns pinned OSCAL documents by URL.
type Loader interface {
	// Load returns the document at the absolute source URL u.
	Load(u string) (map[string]any, error)
}

// PinnedLoader serves the files listed in a MANIFEST.json, keyed by their
// recorded source URL.
type PinnedLoader struct {
	dir    string
	byURL  map[string]string // source URL -> path relative to dir
	byPath map[string]string // path -> source URL
}

// NewPinnedLoader reads dir/MANIFEST.json.
func NewPinnedLoader(dir string) (*PinnedLoader, error) {
	b, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json")) // #nosec G304 -- build-time input directory
	if err != nil {
		return nil, err
	}
	var m struct {
		Files []struct {
			Path   string `json:"path"`
			Source string `json:"source"`
		} `json:"files"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("profilegen: manifest: %w", err)
	}
	l := &PinnedLoader{dir: dir, byURL: map[string]string{}, byPath: map[string]string{}}
	for _, f := range m.Files {
		l.byURL[f.Source] = f.Path
		l.byPath[f.Path] = f.Source
	}
	return l, nil
}

// SourceOf returns the recorded source URL of a pinned path.
func (l *PinnedLoader) SourceOf(path string) (string, bool) {
	u, ok := l.byPath[path]
	return u, ok
}

// Load implements Loader. NIST's examples import XML catalogs; when the URL
// itself is not pinned, the same document's JSON rendition is tried.
func (l *PinnedLoader) Load(u string) (map[string]any, error) {
	for _, cand := range []string{u, jsonRendition(u)} {
		path, ok := l.byURL[cand]
		if !ok {
			continue
		}
		b, err := os.ReadFile(filepath.Join(l.dir, path)) // #nosec G304 -- path comes from the pinned manifest
		if err != nil {
			return nil, err
		}
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("profilegen: %s: %w", path, err)
		}
		return doc, nil
	}
	return nil, fmt.Errorf("profilegen: %s is not pinned in MANIFEST.json (resolution never fetches)", u)
}

// jsonRendition maps NIST's ".../xml/name.xml" to ".../json/name.json".
func jsonRendition(u string) string {
	if !strings.HasSuffix(u, ".xml") {
		return u
	}
	u = strings.TrimSuffix(u, ".xml") + ".json"
	return strings.Replace(u, "/xml/", "/json/", 1)
}

// resolveHref resolves href against the URL of the document containing it.
func resolveHref(base, href string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	h, err := url.Parse(href)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(h).String(), nil
}

// OverlayLoader serves the given documents by URL and everything else from
// Next; used for in-repo profiles, which are not third-party pins.
type OverlayLoader struct {
	Docs map[string]map[string]any
	Next Loader
}

// Load implements Loader.
func (o OverlayLoader) Load(u string) (map[string]any, error) {
	if d, ok := o.Docs[u]; ok {
		return deepCopy(d).(obj), nil
	}
	return o.Next.Load(u)
}
