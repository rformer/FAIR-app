package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the database side (migration 0044): every call carries the
// bearer token's hash, and the database acts only for that token's IdP.
type Store struct {
	DB *pgxpool.Pool // app_rw
}

// provider is the calling token's IdP.
type provider struct {
	IDP              string
	SubjectAttribute string // userName or externalId
}

// record is a stored resource.
type record struct {
	ID       string
	Version  int
	Resource map[string]any
	Created  time.Time
	Updated  time.Time
	Rel      []any // a user's groups, a group's members: [{value, display}]
}

func (s Store) provider(ctx context.Context, th []byte) (provider, error) {
	var p provider
	err := s.DB.QueryRow(ctx, "SELECT idp::text, subject_attribute FROM iam.scim_provider($1)", th).Scan(&p.IDP, &p.SubjectAttribute)
	return p, dbErr(err)
}

func (s Store) list(ctx context.Context, th []byte, k kind, one string) ([]record, error) {
	fn := "iam.scim_user_list"
	if k.Name == "Group" {
		fn = "iam.scim_group_list"
	}
	var arg any
	if one != "" {
		arg = one
	}
	rows, err := s.DB.Query(ctx, "SELECT id::text, version, resource, created_at, updated_at, "+map[bool]string{true: "members", false: "groups"}[k.Name == "Group"]+
		" FROM "+fn+"($1, $2)", th, arg) // #nosec G202 -- fixed function and column names
	if err != nil {
		return nil, dbErr(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (record, error) {
		var rec record
		var res, rel []byte
		if err := r.Scan(&rec.ID, &rec.Version, &res, &rec.Created, &rec.Updated, &rel); err != nil {
			return rec, err
		}
		if err := json.Unmarshal(res, &rec.Resource); err != nil {
			return rec, err
		}
		return rec, json.Unmarshal(rel, &rec.Rel)
	})
	return out, dbErr(err)
}

// userFields are what the database indexes and enforces.
type userFields struct {
	UserName, Subject, ExternalID, Email, DisplayName string
	Active                                            bool
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s Store) writeUser(ctx context.Context, th []byte, id string, ifVersion *int, res map[string]any, f userFields) (record, error) {
	b, err := json.Marshal(res)
	if err != nil {
		return record{}, err
	}
	var rec record
	err = s.DB.QueryRow(ctx, `SELECT id::text, version, created_at, updated_at FROM iam.scim_user_write($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		th, nullable(id), ifVersion, b, f.UserName, nullable(f.Subject), nullable(f.ExternalID), f.Email, f.DisplayName, f.Active).
		Scan(&rec.ID, &rec.Version, &rec.Created, &rec.Updated)
	return rec, dbErr(err)
}

func (s Store) writeGroup(ctx context.Context, th []byte, id string, ifVersion *int, res map[string]any, displayName, externalID string,
	members []string) (record, error) {
	b, err := json.Marshal(res)
	if err != nil {
		return record{}, err
	}
	if members == nil {
		members = []string{}
	}
	var rec record
	err = s.DB.QueryRow(ctx, `SELECT id::text, version, created_at, updated_at FROM iam.scim_group_write($1, $2, $3, $4, $5, $6, $7::uuid[])`,
		th, nullable(id), ifVersion, b, displayName, nullable(externalID), members).Scan(&rec.ID, &rec.Version, &rec.Created, &rec.Updated)
	return rec, dbErr(err)
}

func (s Store) remove(ctx context.Context, th []byte, k kind, id string, ifVersion *int) error {
	fn := "iam.scim_user_delete"
	if k.Name == "Group" {
		fn = "iam.scim_group_delete"
	}
	_, err := s.DB.Exec(ctx, "SELECT "+fn+"($1, $2, $3)", th, id, ifVersion) // #nosec G202 -- fixed function names
	return dbErr(err)
}

// errUnauthorized: no live token.
var errUnauthorized = errors.New("scim: invalid bearer token")

// dbErr maps the database's refusals to SCIM errors.
func dbErr(err error) error {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return err
	}
	switch pg.Code {
	case "PF007":
		return errUnauthorized
	case "PF003":
		return &Error{Status: http.StatusNotFound, Detail: "no such resource"}
	case "PF010":
		return &Error{Status: http.StatusPreconditionFailed, Detail: pg.Message}
	case "PF004", "22P02":
		return bad("invalidValue", "%s", pg.Message)
	case "23505":
		return &Error{Status: http.StatusConflict, ScimType: "uniqueness", Detail: "a resource with that identifier exists"}
	}
	return err
}
