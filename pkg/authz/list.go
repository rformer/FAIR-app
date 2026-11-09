package authz

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// NewestQuery lists the newest rows of a BU-owned table that the caller may
// read (F-001 T-11c, design §4.10). Run its SQL inside WithDBContext: row-level
// security still decides what is visible. The statement picks its shape in
// the database, per statement:
//   - when the caller sees few BUs (the include form, ADR-007 amendment 1), it
//     reads the newest rows of each visible BU through the bu_id index and
//     merges them, so a caller who sees one BU never walks the table;
//   - when the caller sees most BUs (the exclude form), it scans the table in
//     order, where nearly every row is visible.
//
// $1 is the keyset cursor: only rows whose OrderBy value is below it, or NULL
// for the first page. Index the table on (bu_id, OrderBy) when OrderBy is not
// its key.
type NewestQuery struct {
	Table        string   // the BU-owned table, schema-qualified: "risk.register_item"
	ResourceType string   // its resource type, as given to authz.apply_bu_rls
	Columns      []string // the columns returned; must include OrderBy
	OrderBy      string   // a unique column, newest = largest (e.g. "id")
	Limit        int      // rows per page, 1 to MaxListLimit
	// Filter is an optional further condition on the table's rows, written
	// against the alias t (e.g. "t.archived_at IS NULL AND t.owner = $2"),
	// with parameters from $2. It must be a constant of the caller's code,
	// never built from input: values go in parameters.
	Filter string
	// SharedDown lists a table registered shared_down (ADR-007 amendment
	// 2): the include form also walks the BUs the caller inherits from.
	SharedDown bool
}

// MaxListLimit bounds a page.
const MaxListLimit = 1000

var (
	identRE    = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
	tableRE    = regexp.MustCompile(`^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$`)
	resourceRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// ErrInvalidListQuery reports a NewestQuery that cannot be built safely.
var ErrInvalidListQuery = errors.New("authz: invalid list query")

// SQL returns the statement. Identifiers are checked, not quoted: they must
// be plain lower-case names, which need no quoting.
func (q NewestQuery) SQL() (string, error) {
	switch {
	case !tableRE.MatchString(q.Table):
		return "", fmt.Errorf("%w: table %q must be schema.name in lower case", ErrInvalidListQuery, q.Table)
	case !resourceRE.MatchString(q.ResourceType):
		return "", fmt.Errorf("%w: resource type %q", ErrInvalidListQuery, q.ResourceType)
	case !identRE.MatchString(q.OrderBy):
		return "", fmt.Errorf("%w: order column %q", ErrInvalidListQuery, q.OrderBy)
	case len(q.Columns) == 0 || !slices.Contains(q.Columns, q.OrderBy):
		return "", fmt.Errorf("%w: the columns must include the order column %q", ErrInvalidListQuery, q.OrderBy)
	case q.Limit < 1 || q.Limit > MaxListLimit:
		return "", fmt.Errorf("%w: limit %d is not 1 to %d", ErrInvalidListQuery, q.Limit, MaxListLimit)
	}
	seen := map[string]bool{}
	for _, c := range q.Columns {
		if !identRE.MatchString(c) || seen[c] {
			return "", fmt.Errorf("%w: column %q", ErrInvalidListQuery, c)
		}
		seen[c] = true
	}
	cols := func(prefix string) string {
		out := make([]string, len(q.Columns))
		for i, c := range q.Columns {
			out[i] = prefix + c
		}
		return strings.Join(out, ", ")
	}
	excludes := fmt.Sprintf("authz.scope_excludes('%s', 'read')", q.ResourceType)
	// The cursor comparison comes first so that $1 takes the column's type.
	bus := fmt.Sprintf("(SELECT authz.visible_bus('%s', 'read'))::uuid[]", q.ResourceType)
	if q.SharedDown {
		bus = fmt.Sprintf("array_cat((SELECT authz.visible_bus('%[1]s', 'read'))::uuid[], coalesce((SELECT authz.inherited_bus('%[1]s'))::uuid[], '{}'))", q.ResourceType)
	}
	cursor := fmt.Sprintf("(t.%s < $1 OR $1 IS NULL)", q.OrderBy)
	if q.Filter != "" {
		if strings.ContainsAny(q.Filter, ";") || strings.Contains(q.Filter, "--") || strings.Contains(q.Filter, "/*") {
			return "", fmt.Errorf("%w: the filter must be one condition", ErrInvalidListQuery)
		}
		cursor += " AND (" + q.Filter + ")"
	}
	// The form is chosen once (a materialized CTE) and gates both branches;
	// the branch not taken is never executed.
	return fmt.Sprintf(`WITH f AS MATERIALIZED (SELECT %[9]s AS excludes)
SELECT %[1]s FROM (
  SELECT %[2]s FROM unnest(%[10]s) AS v(bu),
    LATERAL (SELECT %[4]s FROM %[5]s t WHERE t.bu_id = v.bu AND %[6]s ORDER BY t.%[7]s DESC LIMIT %[8]d) d
  WHERE NOT (SELECT excludes FROM f)
  UNION ALL
  (SELECT %[4]s FROM %[5]s t WHERE (SELECT excludes FROM f) AND %[6]s ORDER BY t.%[7]s DESC LIMIT %[8]d)
) q ORDER BY %[7]s DESC LIMIT %[8]d`,
		cols(""), cols("d."), q.ResourceType, cols("t."), q.Table, cursor, q.OrderBy, q.Limit, excludes, bus), nil
}
