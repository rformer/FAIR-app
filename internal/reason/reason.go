// Package reason is the export reason rule (F-010 design §3.6, OQ7): a
// reason is required to take risk data out of the platform when the
// setting export.reason_required is true for any business unit the export
// covers. The setting is BU-scopable; F-015's restricted overlay turns it
// on in restricted subtrees. F-010's reports, F-003's risk export and
// F-006's downloads use this one helper.
package reason

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/settings"
)

// Header carries a download's or an export's reason (F-010 T-12), as
// percent-encoded UTF-8 (browsers send only Latin-1 in headers).
const Header = "X-Fair-Reason"

// MaxLen bounds a reason, in characters.
const MaxLen = 500

// Settings reads export.reason_required (settings.Client).
type Settings interface {
	Bool(key, bu string) (bool, error)
	BUValues(key string) (map[string]any, error)
}

// Static is a fixed rule (tests, and installations whose settings say
// so): On everywhere, or at the listed BUs.
type Static struct {
	On  bool
	BUs []string
}

// Bool implements Settings.
func (s Static) Bool(_ string, bu string) (bool, error) {
	return s.On || (bu != "" && slices.Contains(s.BUs, bu)), nil
}

// BUValues implements Settings.
func (s Static) BUValues(string) (map[string]any, error) {
	out := map[string]any{}
	for _, b := range s.BUs {
		out[b] = true
	}
	return out, nil
}

// ErrNotConfigured means there are no settings to decide with (fail closed).
var ErrNotConfigured = errors.New("reason: the export settings are not configured")

// RowQuerier is a pgx.Tx or a pool.
type RowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// InSubtree reports whether a reason is required for an export of bu's
// subtree: the setting is true for bu or any BU below it, restricted ones
// included (report.any_in_subtree). It fails closed.
func InSubtree(ctx context.Context, q RowQuerier, s Settings, bu string) (bool, error) {
	if s == nil {
		return false, ErrNotConfigured
	}
	inst, err := s.Bool(settings.KeyExportReasonRequired, "")
	if err != nil || inst {
		return inst, err
	}
	on, err := onBUs(s)
	if err != nil || len(on) == 0 {
		return false, err
	}
	var found bool
	err = q.QueryRow(ctx, "SELECT report.any_in_subtree($1, $2::uuid[])", bu, on).Scan(&found)
	return found, err
}

// AtBUs reports whether a reason is required for an export of data owned by
// the given BUs: the setting is true at any of them. It fails closed.
func AtBUs(s Settings, bus []string) (bool, error) {
	if s == nil {
		return false, ErrNotConfigured
	}
	if inst, err := s.Bool(settings.KeyExportReasonRequired, ""); err != nil || inst {
		return inst, err
	}
	for _, bu := range bus {
		v, err := s.Bool(settings.KeyExportReasonRequired, bu)
		if err != nil || v {
			return v, err
		}
	}
	return false, nil
}

func onBUs(s Settings) ([]string, error) {
	vals, err := s.BUValues(settings.KeyExportReasonRequired)
	if err != nil {
		return nil, err
	}
	var on []string
	for b, v := range vals {
		if v == true {
			on = append(on, b)
		}
	}
	slices.Sort(on)
	return on, nil
}

// ErrTooLong is a reason over MaxLen characters, or not text.
var ErrTooLong = errors.New("reason: at most 500 characters of text")

// FromRequest is the request's reason (the X-Fair-Reason header, decoded
// and trimmed; "" without one).
func FromRequest(r *http.Request) (string, error) {
	v, err := url.PathUnescape(r.Header.Get(Header))
	if err != nil {
		return "", ErrTooLong
	}
	v = strings.TrimSpace(v)
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) > MaxLen || strings.ContainsAny(v, "\r\n") {
		return "", ErrTooLong
	}
	return v, nil
}
