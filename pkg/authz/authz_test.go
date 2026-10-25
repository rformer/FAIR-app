package authz_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rformer/fair-app/pkg/authz"
)

func TestDenyAllFailsClosed(t *testing.T) {
	p := authz.Principal{ID: "u1", Kind: authz.PrincipalUser}
	for _, c := range []authz.Checker{authz.DenyAll{}, nil} {
		if err := authz.Check(context.Background(), c, p, "analysis.edit", "bu-1"); !errors.Is(err, authz.ErrDenied) {
			t.Fatalf("got %v, want ErrDenied", err)
		}
	}
}

func TestMalformedChecksAreDenied(t *testing.T) {
	ok := authz.Principal{ID: "u1"}
	cases := []struct {
		p    authz.Principal
		perm authz.Permission
		bu   string
	}{
		{authz.Principal{}, "analysis.edit", "bu"},
		{ok, "Analysis.Edit", "bu"},
		{ok, "analysis", "bu"},
		{ok, "analysis.edit", ""},
	}
	for _, c := range cases {
		err := authz.DenyAll{}.Check(context.Background(), c.p, c.perm, c.bu)
		if !errors.Is(err, authz.ErrInvalidRequest) || !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%+v: got %v", c, err)
		}
	}
}

func TestBeginScopedRequiresToken(t *testing.T) {
	if _, err := authz.BeginScoped(context.Background(), nil, ""); !errors.Is(err, authz.ErrNoContext) {
		t.Fatalf("got %v", err)
	}
}
