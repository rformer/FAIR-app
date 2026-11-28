package fleet

import (
	"strings"
	"testing"
)

// F-014 T-10 (design §3.17): the release manifest's mirrors come from the
// third-party list and the copies the release made, each by the
// publisher's digest; a missing, foreign or re-digested copy is refused.
func TestManifestMirrors(t *testing.T) {
	l, err := LoadThirdParty("../../deploy/third-party-images.json")
	if err != nil {
		t.Fatal(err)
	}
	copies := func() map[string]Copy {
		c := map[string]Copy{}
		for _, tp := range l.Images {
			c[tp.Name] = Copy{Source: tp.Repository() + "@" + tp.Digest(),
				Staging: "ghcr.io/rformer/staging/mirror/" + tp.Name + "@" + tp.Digest(),
				Release: "ghcr.io/rformer/mirror/" + tp.Name + "@" + tp.Digest()}
		}
		return c
	}
	ms, err := l.ManifestMirrors(copies())
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != len(l.Images) {
		t.Fatalf("%d mirrors for %d images", len(ms), len(l.Images))
	}
	for i, m := range ms {
		if i > 0 && ms[i-1].Component >= m.Component {
			t.Errorf("not sorted: %s", m.Component)
		}
		tp := l.Images[0]
		for _, x := range l.Images {
			if x.Name == m.Component {
				tp = x
			}
		}
		if m.Image != "ghcr.io/rformer/mirror/"+tp.Name+"@"+tp.Digest() || m.Source != tp.Image || m.Identity != tp.Identity || m.Issuer != tp.Issuer {
			t.Errorf("%+v for %+v", m, tp)
		}
	}
	name := l.Images[0].Name
	other := "sha256:" + strings.Repeat("9", 64)
	for label, edit := range map[string]func(map[string]Copy){
		"missing":  func(c map[string]Copy) { delete(c, name) },
		"unlisted": func(c map[string]Copy) { c["stray"] = c[name] },
		"other source": func(c map[string]Copy) {
			x := c[name]
			x.Source = "docker.io/evil/x@" + l.Images[0].Digest()
			c[name] = x
		},
		"other digest": func(c map[string]Copy) {
			x := c[name]
			x.Release = "ghcr.io/rformer/mirror/" + name + "@" + other
			c[name] = x
		},
		"staging moved": func(c map[string]Copy) {
			x := c[name]
			x.Staging = "ghcr.io/rformer/staging/mirror/" + name + "@" + other
			c[name] = x
		},
	} {
		c := copies()
		edit(c)
		if _, err := l.ManifestMirrors(c); err == nil {
			t.Errorf("%s: accepted", label)
		}
	}
}
