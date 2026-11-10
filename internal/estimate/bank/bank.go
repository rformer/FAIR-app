// Package bank is the calibration question bank shipped with each release
// (F-004 AC-24; design §6.6): general-knowledge questions on stable facts,
// each with its answer and a citable source. iam migrate syncs it into a
// read-only shipped question set (estimate.sync_bank); customers add their
// own sets beside it.
package bank

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/rformer/fair-app/internal/risk/canon"
	"github.com/rformer/fair-app/pkg/audit"
)

//go:embed questions.json
var content []byte

// Question is one shipped question.
type Question struct {
	Key    string `json:"key"`
	Kind   string `json:"kind"` // range or binary
	Text   string `json:"text"`
	Unit   string `json:"unit,omitempty"`
	Answer string `json:"answer"` // a canonical decimal (range), or true or false (binary)
	Source string `json:"source"`
}

// Bank is the shipped bank of a release.
type Bank struct {
	Release     string     `json:"release"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Questions   []Question `json:"questions"`
}

var keyRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Load parses and checks the embedded bank.
func Load() (Bank, error) { return Parse(content) }

// Parse parses and checks a bank: unique keys and texts, each question
// with its text, unit (ranges), answer and source, nothing that looks like
// a secret.
func Parse(b []byte) (Bank, error) {
	var bk Bank
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&bk); err != nil {
		return bk, fmt.Errorf("bank: %w", err)
	}
	if strings.TrimSpace(bk.Release) == "" || strings.TrimSpace(bk.Name) == "" || len(bk.Questions) == 0 {
		return bk, errors.New("bank: a release, a name and questions are required")
	}
	keys, texts := map[string]bool{}, map[string]bool{}
	text := func(q Question, field, s string, max int) error {
		switch {
		case strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > max:
			return fmt.Errorf("bank: %s: %s is required, at most %d characters", q.Key, field, max)
		case strings.ContainsAny(s, "\r\n"):
			return fmt.Errorf("bank: %s: %s is a single line", q.Key, field)
		case audit.LooksSecret(s):
			return fmt.Errorf("bank: %s: %s looks like a secret", q.Key, field)
		}
		return nil
	}
	for _, q := range bk.Questions {
		switch {
		case !keyRE.MatchString(q.Key):
			return bk, fmt.Errorf("bank: bad key %q", q.Key)
		case keys[q.Key]:
			return bk, fmt.Errorf("bank: %s listed twice", q.Key)
		case texts[q.Text]:
			return bk, fmt.Errorf("bank: %s: the same question is asked twice", q.Key)
		}
		keys[q.Key], texts[q.Text] = true, true
		if err := text(q, "text", q.Text, 1000); err != nil {
			return bk, err
		}
		if err := text(q, "source", q.Source, 1000); err != nil {
			return bk, err
		}
		switch q.Kind {
		case "range":
			if err := text(q, "unit", q.Unit, 100); err != nil {
				return bk, err
			}
			if c, err := canon.Decimal(q.Answer); err != nil || c != q.Answer {
				return bk, fmt.Errorf("bank: %s: a range question's answer is a canonical decimal, not %q", q.Key, q.Answer)
			}
		case "binary":
			if q.Unit != "" {
				return bk, fmt.Errorf("bank: %s: a true-or-false question has no unit", q.Key)
			}
			if q.Answer != "true" && q.Answer != "false" {
				return bk, fmt.Errorf("bank: %s: a true-or-false question's answer is true or false", q.Key)
			}
		default:
			return bk, fmt.Errorf("bank: %s: kind is range or binary", q.Key)
		}
	}
	return bk, nil
}

// id is a stable UUID for a name (an RFC 4122 version 5 layout over
// SHA-256), so a question keeps its id from release to release.
func id(name string) string {
	h := sha256.Sum256([]byte("fair:calibration:" + name))
	h[6] = h[6]&0x0f | 0x50
	h[8] = h[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// SetID is the shipped set's id.
var SetID = id("shipped-set")

// QuestionID is a shipped question's id.
func QuestionID(key string) string { return id("shipped:" + key) }

// SyncPayload is the JSON passed to estimate.sync_bank at migrate.
func SyncPayload() ([]byte, error) {
	bk, err := Load()
	if err != nil {
		return nil, err
	}
	type item struct {
		ID     string  `json:"id"`
		Key    string  `json:"key"`
		Kind   string  `json:"kind"`
		Text   string  `json:"text"`
		Unit   *string `json:"unit"`
		Answer string  `json:"answer"`
		Source string  `json:"source"`
	}
	out := struct {
		SetID       string `json:"set_id"`
		Release     string `json:"release"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Questions   []item `json:"questions"`
	}{SetID: SetID, Release: bk.Release, Name: bk.Name, Description: bk.Description}
	for _, q := range bk.Questions {
		it := item{ID: QuestionID(q.Key), Key: q.Key, Kind: q.Kind, Text: q.Text, Answer: q.Answer, Source: q.Source}
		if q.Unit != "" {
			u := q.Unit
			it.Unit = &u
		}
		out.Questions = append(out.Questions, it)
	}
	return json.Marshal(out)
}
