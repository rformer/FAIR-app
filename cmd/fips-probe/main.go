// Command fips-probe reports whether its node's kernel runs in FIPS mode
// (F-015 T-29, design D-OQ2). It runs as a DaemonSet with exactly one
// host file mounted read-only (/proc/sys/crypto/fips_enabled) and reports
// through its readiness: the readiness probe runs "fips-probe check", which
// succeeds only when the flag reads 1. posture-scanner reads the probe
// pods' readiness per node. The probe needs no credentials, no network and
// no RBAC, and does no cryptography.
//
//	fips-probe [serve]   log the flag every 10 minutes until terminated
//	fips-probe check     exit 0 if the flag is 1, else 1 (readiness probe)
//
// FAIR_FIPS_FLAG_FILE overrides the flag path (default /host/fips_enabled).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const defaultFlagFile = "/host/fips_enabled"

func main() {
	file := os.Getenv("FAIR_FIPS_FLAG_FILE")
	if file == "" {
		file = defaultFlagFile
	}
	mode := "serve"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "check":
		if on, err := fipsEnabled(file); err != nil || !on {
			fmt.Fprintln(os.Stderr, "fips-probe: FIPS mode not confirmed:", describe(on, err))
			os.Exit(1)
		}
	case "serve":
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		serve(ctx, file, 10*time.Minute)
	default:
		fmt.Fprintln(os.Stderr, "usage: fips-probe [serve|check]")
		os.Exit(2)
	}
}

// fipsEnabled reads the kernel's FIPS flag: exactly "1" (with an optional
// newline) is on, "0" is off; anything else is an error.
func fipsEnabled(file string) (bool, error) {
	b, err := os.ReadFile(file) // #nosec G304 G703 -- the mounted kernel flag (operator-set path)
	if err != nil {
		return false, err
	}
	switch strings.TrimSuffix(string(b), "\n") {
	case "1":
		return true, nil
	case "0":
		return false, nil
	}
	return false, errors.New("unexpected content in the FIPS flag file")
}

func describe(on bool, err error) string {
	if err != nil {
		return err.Error()
	}
	if on {
		return "enabled"
	}
	return "disabled"
}

func serve(ctx context.Context, file string, every time.Duration) {
	logState := func() {
		on, err := fipsEnabled(file)
		b, _ := json.Marshal(map[string]any{"service": "fips-probe", "node": os.Getenv("NODE_NAME"), "fips_enabled": on,
			"state": describe(on, err), "time": time.Now().UTC().Format(time.RFC3339)})
		_, _ = os.Stdout.Write(append(b, '\n'))
	}
	logState()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			logState()
		}
	}
}
