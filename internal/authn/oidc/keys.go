package oidc

import (
	"context"
	"sync"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
)

// keyCache keeps one remote key set per JWKS URI, so its keys are cached
// across logins and refetched when an unknown key ID appears (rotation).
type keyCache struct {
	mu   sync.Mutex
	sets map[string]*gooidc.RemoteKeySet
}

// get returns the key set of uri. ctx carries the HTTP client
// (gooidc.ClientContext) and outlives the request: go-oidc keeps it for
// later fetches.
func (c *keyCache) get(ctx context.Context, uri string) *gooidc.RemoteKeySet {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sets == nil {
		c.sets = map[string]*gooidc.RemoteKeySet{}
	}
	s, ok := c.sets[uri]
	if !ok {
		s = gooidc.NewRemoteKeySet(context.WithoutCancel(ctx), uri)
		c.sets[uri] = s
	}
	return s
}
