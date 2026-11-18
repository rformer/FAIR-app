// Package integration is F-011's records: the documented batch format
// (fair.integration.v1), CSV with declarative column mappings, and the
// typed validation of the five record kinds (design §3.2). A batch is
// checked record by record: a refused record is reported with its position
// and the JSON pointer of the problem, and the valid ones go on (AC-06).
// Records are normalized (decimals canonical, text trimmed) and carry the
// canonical form's digest, so an unchanged source record is recognized
// (AC-12).
package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/mail"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rformer/fair-app/internal/risk/canon"
	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/pkg/audit"
)

// Format names the batch format.
const Format = "fair.integration.v1"

// Limits (OQ8, design §3.2).
const (
	MaxRecords  = 10_000
	MaxBody     = 20 << 20
	MaxRefusals = 1_000
	MaxMembers  = 1_000
)

// Input kinds (an integration's) and record kinds (a record's).
const (
	InputAssets        = "assets"
	InputLossEvents    = "loss_events"
	InputRisks         = "risks"
	InputControlStatus = "control_status"

	KindAsset         = "asset"
	KindAssetGroup    = "asset_group"
	KindLossEvent     = "loss_event"
	KindRisk          = "risk"
	KindControlStatus = "control_status"
)

// InputKinds are the integrations' input kinds.
var InputKinds = []string{InputAssets, InputLossEvents, InputRisks, InputControlStatus}

// RecordKinds are the record kinds each input kind takes; the first is the
// kind of a CSV row.
var RecordKinds = map[string][]string{
	InputAssets:        {KindAsset, KindAssetGroup},
	InputLossEvents:    {KindLossEvent},
	InputRisks:         {KindRisk},
	InputControlStatus: {KindControlStatus},
}

// Range is a calibrated range from a source (an asset's or group's value):
// the platform completes it into an estimate (unit currency, the
// integration as its source) when it proposes the record.
type Range struct {
	Min        model.Decimal `json:"min"`
	ML         model.Decimal `json:"ml"`
	Max        model.Decimal `json:"max"`
	Confidence model.Decimal `json:"confidence,omitempty"`
	Basis      string        `json:"basis,omitempty"`
}

// Asset is an asset record (AC-15).
type Asset struct {
	Kind        string `json:"kind"`
	ExternalID  string `json:"external_id"`
	BU          string `json:"bu"`
	Name        string `json:"name"`
	AssetType   string `json:"asset_type"`
	Description string `json:"description,omitempty"`
	Value       *Range `json:"value,omitempty"`
}

// AssetGroup is an asset group record: its members are assets' external
// IDs of the same integration (AC-16).
type AssetGroup struct {
	Kind        string   `json:"kind"`
	ExternalID  string   `json:"external_id"`
	BU          string   `json:"bu"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members"`
	Value       *Range   `json:"value,omitempty"`
}

// LossEvent is a loss event record (AC-17): amounts by FAIR form of loss
// in the installation currency.
type LossEvent struct {
	Kind        string                   `json:"kind"`
	ExternalID  string                   `json:"external_id"`
	BU          string                   `json:"bu"`
	OccurredOn  string                   `json:"occurred_on"`
	EventType   string                   `json:"event_type"`
	Description string                   `json:"description,omitempty"`
	Amounts     map[string]model.Decimal `json:"amounts,omitempty"`
}

// Risk is a register risk record (AC-20): no exposure, no ratings.
type Risk struct {
	Kind        string `json:"kind"`
	ExternalID  string `json:"external_id"`
	BU          string `json:"bu"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Owner       string `json:"owner,omitempty"`    // an email address
	Category    string `json:"category,omitempty"` // a category's name
}

// ControlStatus is a control's implementation status (AC-23). Control
// names the platform control the first time an external ID is seen;
// after that the link decides.
type ControlStatus struct {
	Kind       string `json:"kind"`
	ExternalID string `json:"external_id"`
	Control    string `json:"control,omitempty"`
	Status     string `json:"status"`
	AssessedOn string `json:"assessed_on"`
	Note       string `json:"note,omitempty"`
}

// Record is a valid, normalized record.
type Record struct {
	N          int             `json:"n"` // 1-based position in the batch (a CSV's data row)
	Kind       string          `json:"kind"`
	ExternalID string          `json:"external_id"`
	BU         string          `json:"bu,omitempty"`
	Data       json.RawMessage `json:"data"`   // the record, canonical
	Digest     string          `json:"digest"` // SHA-256 of Data
}

// Refusal is a record that was not taken (AC-06).
type Refusal struct {
	N          int    `json:"n"`
	ExternalID string `json:"external_id,omitempty"`
	Column     string `json:"column,omitempty"` // CSV only: the column of the field
	Pointer    string `json:"pointer"`
	Message    string `json:"message"`
}

// Batch is a parsed batch: its valid records and its refusals.
type Batch struct {
	Complete bool
	Records  []Record
	Refused  []Refusal // at most MaxRefusals kept
	Refusals int       // all of them
}

func (b *Batch) refuse(r Refusal) {
	b.Refusals++
	if len(b.Refused) < MaxRefusals {
		b.Refused = append(b.Refused, r)
	}
}

// ErrBatch is a batch refused whole (not records one by one).
var ErrBatch = errors.New("integration: batch refused")

func batchError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBatch, fmt.Sprintf(format, args...))
}

// ParseJSON parses a fair.integration.v1 batch for an integration of the
// given input kind.
func ParseJSON(raw []byte, input string) (*Batch, error) {
	if len(raw) > MaxBody {
		return nil, batchError("the batch is larger than %d bytes", MaxBody)
	}
	allowed, ok := RecordKinds[input]
	if !ok {
		return nil, batchError("unknown input kind %q", input)
	}
	generic, err := canon.Parse(raw)
	if err != nil {
		return nil, batchError("not a JSON document: %v", err)
	}
	top, ok := generic.(map[string]any)
	if !ok {
		return nil, batchError("not a JSON object")
	}
	for k := range top {
		if k != "format" && k != "complete" && k != "records" {
			return nil, batchError("unknown member %q", k)
		}
	}
	if top["format"] != Format {
		return nil, batchError("format is not %q", Format)
	}
	b := &Batch{}
	if c, ok := top["complete"]; ok {
		if b.Complete, ok = c.(bool); !ok {
			return nil, batchError("complete is not a boolean")
		}
	}
	recs, ok := top["records"].([]any)
	if !ok {
		return nil, batchError("records is not an array")
	}
	if len(recs) > MaxRecords {
		return nil, batchError("%d records; at most %d in a batch", len(recs), MaxRecords)
	}
	seen := map[string]int{}
	for i, r := range recs {
		one, _ := json.Marshal(r) // values from canon.Parse always marshal
		b.add(i+1, one, allowed, seen, nil)
	}
	return b, nil
}

// add checks one record and keeps it or its refusal.
func (b *Batch) add(n int, raw []byte, allowed []string, seen map[string]int, columns map[string]string) {
	var head struct {
		Kind       string `json:"kind"`
		ExternalID string `json:"external_id"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		b.refuse(Refusal{N: n, Pointer: "", Message: "not a record object"})
		return
	}
	refuse := func(p model.Problem) {
		b.refuse(Refusal{N: n, ExternalID: head.ExternalID, Column: columnOf(columns, p.Pointer), Pointer: p.Pointer, Message: p.Message})
	}
	if !slices.Contains(allowed, head.Kind) {
		refuse(model.Problem{Pointer: "/kind", Message: fmt.Sprintf("is %q, want one of %s", head.Kind, strings.Join(allowed, ", "))})
		return
	}
	rec, problems := Validate(head.Kind, raw)
	if len(problems) > 0 {
		for _, p := range problems {
			refuse(p)
		}
		return
	}
	if first, dup := seen[rec.ExternalID]; dup {
		refuse(model.Problem{Pointer: "/external_id", Message: fmt.Sprintf("appears earlier in the batch, at record %d", first)})
		return
	}
	seen[rec.ExternalID] = n
	rec.N = n
	b.Records = append(b.Records, rec)
}

// Validate checks one record of kind and returns it normalized, or every
// problem by JSON pointer.
func Validate(kind string, raw []byte) (Record, model.Problems) {
	var v checker
	var out any
	var ext, bu string
	switch kind {
	case KindAsset:
		var r Asset
		if !v.decode(raw, &r) {
			return Record{}, v.problems
		}
		v.header(&r.ExternalID, &r.BU, true)
		v.text("/name", &r.Name, model.MaxName, true, false)
		v.text("/asset_type", &r.AssetType, model.MaxName, true, false)
		v.text("/description", &r.Description, model.MaxText, false, true)
		v.value("/value", r.Value)
		out, ext, bu = r, r.ExternalID, r.BU
	case KindAssetGroup:
		var r AssetGroup
		if !v.decode(raw, &r) {
			return Record{}, v.problems
		}
		v.header(&r.ExternalID, &r.BU, true)
		v.text("/name", &r.Name, model.MaxName, true, false)
		v.text("/description", &r.Description, model.MaxText, false, true)
		switch {
		case len(r.Members) == 0:
			v.add("/members", "at least one member is required")
		case len(r.Members) > MaxMembers:
			v.add("/members", "at most %d members", MaxMembers)
		}
		seen := map[string]bool{}
		for i := range r.Members {
			p := fmt.Sprintf("/members/%d", i)
			v.externalID(p, &r.Members[i])
			if seen[r.Members[i]] {
				v.add(p, "is listed twice")
			}
			seen[r.Members[i]] = true
		}
		v.value("/value", r.Value)
		out, ext, bu = r, r.ExternalID, r.BU
	case KindLossEvent:
		var r LossEvent
		if !v.decode(raw, &r) {
			return Record{}, v.problems
		}
		v.header(&r.ExternalID, &r.BU, true)
		v.date("/occurred_on", r.OccurredOn)
		v.text("/event_type", &r.EventType, 100, true, false)
		v.text("/description", &r.Description, 2000, false, true)
		for form, amount := range r.Amounts {
			p := "/amounts/" + form
			if !slices.Contains(model.FormsOfLoss, form) {
				v.add(p, "is not a form of loss (want one of %s)", strings.Join(model.FormsOfLoss, ", "))
				continue
			}
			r.Amounts[form] = v.amount(p, amount)
		}
		out, ext, bu = r, r.ExternalID, r.BU
	case KindRisk:
		var r Risk
		if !v.decode(raw, &r) {
			return Record{}, v.problems
		}
		v.header(&r.ExternalID, &r.BU, true)
		v.text("/title", &r.Title, model.MaxName, true, false)
		v.text("/description", &r.Description, model.MaxText, false, true)
		if r.Owner = strings.TrimSpace(r.Owner); r.Owner != "" {
			if a, err := mail.ParseAddress(r.Owner); err != nil || a.Address != r.Owner || len(r.Owner) > 254 {
				v.add("/owner", "is not an email address")
			}
		}
		v.text("/category", &r.Category, 100, false, false)
		out, ext, bu = r, r.ExternalID, r.BU
	case KindControlStatus:
		var r ControlStatus
		if !v.decode(raw, &r) {
			return Record{}, v.problems
		}
		none := ""
		v.header(&r.ExternalID, &none, false)
		if r.Control != "" && !uuidRE.MatchString(r.Control) {
			v.add("/control", "is not a control id")
		}
		if !slices.Contains(model.ImplementationStatuses, r.Status) {
			v.add("/status", "is %q, want one of %s", r.Status, strings.Join(model.ImplementationStatuses, ", "))
		}
		v.date("/assessed_on", r.AssessedOn)
		v.text("/note", &r.Note, model.MaxLine, false, false)
		out, ext = r, r.ExternalID
	default:
		return Record{}, model.Problems{{Pointer: "/kind", Message: fmt.Sprintf("is %q, not a record kind", kind)}}
	}
	if len(v.problems) > 0 {
		return Record{}, v.problems
	}
	data, err := json.Marshal(out)
	if err == nil {
		data, err = canon.Canonicalize(data)
	}
	if err != nil {
		return Record{}, model.Problems{{Pointer: "", Message: "cannot write the canonical form: " + err.Error()}}
	}
	return Record{Kind: kind, ExternalID: ext, BU: bu, Data: data, Digest: canon.Digest(data)}, nil
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type checker struct{ problems model.Problems }

func (v *checker) add(ptr, format string, args ...any) {
	v.problems = append(v.problems, model.Problem{Pointer: ptr, Message: fmt.Sprintf(format, args...)})
}

// decode decodes raw into r, refusing unknown fields (by pointer).
func (v *checker) decode(raw []byte, r any) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(r); err != nil {
		var ute *json.UnmarshalTypeError
		switch {
		case errors.As(err, &ute):
			v.add("/"+strings.ReplaceAll(ute.Field, ".", "/"), "has the wrong type (want %s)", ute.Type)
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			f := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
			v.add("/"+f, "is not a field of this record")
		default:
			v.add("", "is not a valid record: %v", err)
		}
		return false
	}
	return true
}

func (v *checker) header(ext, bu *string, needBU bool) {
	v.externalID("/external_id", ext)
	*bu = strings.TrimSpace(*bu)
	switch {
	case needBU && *bu == "":
		v.add("/bu", "is required (a business unit's code or id)")
	case len(*bu) > 64:
		v.add("/bu", "is longer than 64 characters")
	}
}

func (v *checker) externalID(ptr string, s *string) {
	*s = strings.TrimSpace(*s)
	switch {
	case *s == "":
		v.add(ptr, "is required")
	case utf8.RuneCountInString(*s) > 256:
		v.add(ptr, "is longer than 256 characters")
	case strings.IndexFunc(*s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0:
		v.add(ptr, "contains a control character")
	}
}

// text trims s and checks it as model.Validate checks document text.
func (v *checker) text(ptr string, s *string, max int, required, multiline bool) {
	*s = strings.TrimSpace(*s)
	switch {
	case required && *s == "":
		v.add(ptr, "is required")
		return
	case utf8.RuneCountInString(*s) > max:
		v.add(ptr, "is longer than %d characters", max)
		return
	}
	for _, r := range *s {
		if r == '\n' || r == '\r' {
			if !multiline {
				v.add(ptr, "must be a single line")
				return
			}
			continue
		}
		if (r < 0x20 && r != '\t') || r == 0x7f {
			v.add(ptr, "contains a control character")
			return
		}
	}
	if audit.LooksSecret(*s) {
		v.add(ptr, "looks like a secret; secrets do not belong in risk data")
	}
}

func (v *checker) date(ptr, s string) {
	if _, err := time.Parse(time.DateOnly, s); err != nil {
		v.add(ptr, "must be a date (YYYY-MM-DD)")
	}
}

// amount is a non-negative decimal of at most 18 integer and 6 fraction
// digits (integration.valid_amounts), canonical.
func (v *checker) amount(ptr string, d model.Decimal) model.Decimal {
	c, err := canon.Decimal(string(d))
	if err != nil {
		v.add(ptr, "is not a decimal number")
		return d
	}
	if !amountRE.MatchString(c) {
		v.add(ptr, "must be at least 0, with at most 18 digits before the point and 6 after")
	}
	return model.Decimal(c)
}

var amountRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})(\.[0-9]{1,6})?$`)

// value checks a range: min <= ml <= max, all at least 0; a confidence
// above 0 and below 1.
func (v *checker) value(ptr string, r *Range) {
	if r == nil {
		return
	}
	var nums [3]*big.Rat
	ok := true
	for i, x := range []*model.Decimal{&r.Min, &r.ML, &r.Max} {
		p := ptr + "/" + []string{"min", "ml", "max"}[i]
		before := len(v.problems)
		*x = v.amount(p, *x)
		nums[i], _ = new(big.Rat).SetString(string(*x))
		ok = ok && len(v.problems) == before && nums[i] != nil
	}
	if ok && (nums[0].Cmp(nums[1]) > 0 || nums[1].Cmp(nums[2]) > 0) {
		v.add(ptr, "must have min <= ml <= max")
	}
	if r.Confidence != "" {
		c, err := canon.Decimal(string(r.Confidence))
		var f *big.Rat
		if err == nil {
			f, _ = new(big.Rat).SetString(c)
		}
		if f == nil || f.Sign() <= 0 || f.Cmp(big.NewRat(1, 1)) >= 0 {
			v.add(ptr+"/confidence", "must be above 0 and below 1")
		} else {
			r.Confidence = model.Decimal(c)
		}
	}
	v.text(ptr+"/basis", &r.Basis, model.MaxLine, false, false)
}

func columnOf(columns map[string]string, pointer string) string {
	if columns == nil {
		return ""
	}
	return columns[strings.TrimPrefix(pointer, "/")]
}

// Reject drops the records check refuses (business units outside the
// integration's subtree, T-08), recording each refusal; refusals stay in
// position order.
func (b *Batch) Reject(check func(Record) (pointer, message string, refused bool)) {
	kept := b.Records[:0]
	for _, r := range b.Records {
		if p, m, bad := check(r); bad {
			b.refuse(Refusal{N: r.N, ExternalID: r.ExternalID, Pointer: p, Message: m})
			continue
		}
		kept = append(kept, r)
	}
	b.Records = kept
	sort.SliceStable(b.Refused, func(i, j int) bool { return b.Refused[i].N < b.Refused[j].N })
}

// Received is how many records the batch held.
func (b *Batch) Received() int { return len(b.Records) + b.Refusals }
