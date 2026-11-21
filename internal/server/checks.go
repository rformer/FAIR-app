package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// KeyFiles is a readiness check that the key files and directories named
// by the environment variables given are still present (F-012 T-09,
// F-012-AC-22: readiness covers keys). Variables that are unset are not
// checked; the service's configuration decided at start whether they were
// required. A secret store that stops delivering a key makes the service
// unready instead of failing requests later.
func KeyFiles(getenv func(string) string, vars ...string) ReadinessCheck {
	return ReadinessCheck{Name: "keys", Check: func(context.Context) error {
		var errs []error
		for _, v := range vars {
			p := getenv(v)
			if p == "" {
				continue
			}
			fi, err := os.Stat(p)
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("%s: %w", v, err))
			case fi.IsDir():
				ents, err := os.ReadDir(p)
				if err != nil || len(ents) == 0 {
					errs = append(errs, fmt.Errorf("%s: %s is empty or unreadable", v, p))
				}
			case fi.Size() == 0:
				errs = append(errs, fmt.Errorf("%s: %s is empty", v, p))
			}
		}
		return errors.Join(errs...)
	}}
}

// Every runs check at most once per interval, reusing a success in between
// (for checks that call a remote service, such as object storage or the
// engine). A failure is never reused: the next probe checks again.
func Every(interval time.Duration, c ReadinessCheck) ReadinessCheck {
	var mu sync.Mutex
	var okUntil time.Time
	inner := c.Check
	c.Check = func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if time.Now().Before(okUntil) {
			return nil
		}
		if err := inner(ctx); err != nil {
			return err
		}
		okUntil = time.Now().Add(interval)
		return nil
	}
	return c
}
