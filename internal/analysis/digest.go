package analysis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/rformer/fair-app/internal/risk/canon"
)

// RunInputs are the run's recorded inputs, as the digest covers them.
type RunInputs struct {
	ScenarioID   string   `json:"scenario_id"`
	Version      int64    `json:"scenario_version"`
	BundleDigest string   `json:"bundle_digest"`
	Seed         string   `json:"seed"` // decimal: it may exceed 2^53
	Iterations   int      `json:"iterations"`
	ControlSets  []string `json:"control_sets"`
}

// SetResult is one control set's summary (JSON, as the engine sent it) and
// series (float64 little-endian).
type SetResult struct {
	ControlSet string
	Summary    []byte
	Series     []byte
}

// Digest is the results digest (design §6.3): SHA-256 of the canonical
// form (F-003 canon) of {run inputs, engine version, architecture, per set:
// summary, SHA-256 of the series bytes}. Canonical documents hold integers
// only, so every other number of a summary becomes the string of its
// shortest round-trip decimal: the digest depends on the values computed,
// not on how they were written.
func Digest(in RunInputs, engineVersion, architecture string, sets []SetResult) (string, error) {
	out := make([]any, 0, len(sets))
	for _, s := range sets {
		v, err := canon.Parse(s.Summary)
		if err != nil {
			return "", fmt.Errorf("analysis: summary of %s: %w", s.ControlSet, err)
		}
		norm, err := normalize(v)
		if err != nil {
			return "", fmt.Errorf("analysis: summary of %s: %w", s.ControlSet, err)
		}
		sum := sha256.Sum256(s.Series)
		out = append(out, map[string]any{"control_set": s.ControlSet, "summary": norm, "series_sha256": hex.EncodeToString(sum[:])})
	}
	sets2 := make([]any, len(in.ControlSets))
	for i, s := range in.ControlSets {
		sets2[i] = s
	}
	doc := map[string]any{
		"format": "fair.analysis-result.v1",
		"run": map[string]any{
			"scenario_id": in.ScenarioID, "scenario_version": in.Version, "bundle_digest": in.BundleDigest,
			"seed": in.Seed, "iterations": int64(in.Iterations), "control_sets": sets2,
		},
		"engine": map[string]any{"version": engineVersion, "architecture": architecture},
		"sets":   out,
	}
	b, err := canon.Marshal(doc)
	if err != nil {
		return "", err
	}
	return canon.Digest(b), nil
}

func normalize(v any) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			n, err := normalize(e)
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			n, err := normalize(e)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case json.Number:
		s := string(x)
		if !strings.ContainsAny(s, ".eE") {
			if i, err := strconv.ParseInt(s, 10, 64); err == nil && i <= canon.MaxSafeInteger && i >= -canon.MaxSafeInteger {
				return i, nil
			}
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, fmt.Errorf("the number %s is not a finite float64", s)
		}
		return strconv.FormatFloat(f, 'g', -1, 64), nil
	}
	return v, nil
}

// checkSeries refuses a series of the wrong length or with a value that is
// not finite (or negative: annual losses are not).
func checkSeries(b []byte, iterations int) error {
	if len(b) != iterations*8 {
		return fmt.Errorf("%d bytes, want %d float64 values", len(b), iterations)
	}
	for i := 0; i < len(b); i += 8 {
		f := math.Float64frombits(uint64(b[i]) | uint64(b[i+1])<<8 | uint64(b[i+2])<<16 | uint64(b[i+3])<<24 |
			uint64(b[i+4])<<32 | uint64(b[i+5])<<40 | uint64(b[i+6])<<48 | uint64(b[i+7])<<56)
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
			return fmt.Errorf("value %d is %v", i/8, f)
		}
	}
	return nil
}

// checkSummary refuses a summary that is not one JSON object.
func checkSummary(b []byte) error {
	v, err := canon.Parse(b)
	if err != nil {
		return err
	}
	if _, ok := v.(map[string]any); !ok {
		return errors.New("not a JSON object")
	}
	if !bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		return errors.New("not a JSON object")
	}
	return nil
}
