package installer

import (
	"regexp"
	"strings"

	"github.com/rformer/fair-app/pkg/audit"
)

// tokenShapes are credentials by their well-known shapes, beyond what
// audit.LooksSecret matches (JWTs, PEM private keys, bearer and basic
// credentials, the session cookie): any PEM block (certificates and keys
// are given as files), credentials in URLs, provider token prefixes.
var tokenShapes = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----` +
	`|://[^/\s:@]+:[^/\s@]+@` + // user:password@ in a URL
	`|\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,})` +
	`|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b` +
	`|\bhv[sbr]\.[A-Za-z0-9_-]{20,}` + // OpenBao/Vault tokens
	`|\bxox[abprs]-[A-Za-z0-9-]{10,}` +
	`|\bsk-[A-Za-z0-9_-]{20,}` +
	`|\bAIza[0-9A-Za-z_-]{35}` +
	`|\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`)

// opaque matches a long run of base64 or base64url characters ('/' is left
// out, so that paths are read segment by segment).
var opaque = regexp.MustCompile(`[A-Za-z0-9+_-]{32,}`)

// LooksSecret reports whether s looks like a secret value: audit.LooksSecret,
// the token shapes above, or a long opaque string mixing upper case, lower
// case and digits (a random key or password; hex digests and words do not
// mix all three).
func LooksSecret(s string) bool {
	if audit.LooksSecret(s) || tokenShapes.MatchString(s) {
		return true
	}
	for _, m := range opaque.FindAllString(s, -1) {
		if strings.ContainsAny(m, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") && strings.ContainsAny(m, "abcdefghijklmnopqrstuvwxyz") &&
			strings.ContainsAny(m, "0123456789") {
			return true
		}
	}
	return false
}

// secretNames are key fragments naming a secret; a key holding one is a
// file path (its name ends in _file) or refused.
var secretNames = []string{"password", "passwd", "secret", "token", "private_key", "api_key", "apikey", "bearer", "credential", "access_key"}

// secretKey reports whether a key names a secret held inline.
func secretKey(k string) bool {
	k = strings.ToLower(k)
	if strings.HasSuffix(k, "_file") {
		return false
	}
	for _, n := range secretNames {
		if strings.Contains(k, n) {
			return true
		}
	}
	return false
}
