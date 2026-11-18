package notify

import "github.com/rformer/fair-app/internal/egress"

// F-009 T-08 (F-009-AC-10; design §3.4): the destination guard lives in
// internal/egress since F-011 T-04, shared with F-011's connectors; these
// names keep notify's callers as they were.

// Guard checks and dials destinations (egress.Guard); notify's sets Setting
// to notification.allowed_hosts.
type Guard = egress.Guard

// ErrRefused is a destination the guard refuses.
var ErrRefused = egress.ErrRefused

// Timeout bounds a connection and each exchange (design §3.4).
const Timeout = egress.Timeout

// MaxResponse is the most of a webhook's response read (design §3.4).
const MaxResponse = 64 << 10

// HostAllowed reports whether host matches the allow-list.
func HostAllowed(allowed []string, host string) bool { return egress.HostAllowed(allowed, host) }

// CheckHostPattern refuses an allow-list entry that is not a host name, a
// "*.suffix", "*" or an IP address (design §4).
func CheckHostPattern(p string) error { return egress.CheckHostPattern(p) }
