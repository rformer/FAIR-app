// Package posture holds the posture service's database operations (F-015).
// Every write goes through the SECURITY DEFINER functions in schema posture
// (design §5 access model); the connection must be app_posture.
package posture

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// DefaultProfile is the installer's default selection (AC-09).
const DefaultProfile = settings.ProfileFedRAMPModerate

// ManifestFile is a signed release's manifest name (profilegen sign).
const ManifestFile = "manifest.json"

// Seeded describes an install-time seed.
type Seeded struct {
	Profile, Version, Digest string
	Settings                 int
}

// Seed makes the selected built-in profile active and seeds every setting's
// instance value from it (AC-09, AC-10). version "" selects the only loaded
// version. The audit event is emitted inside the transaction: if it cannot
// be recorded, nothing is seeded (audit failures fail closed, ADR-006).
func Seed(ctx context.Context, pool *pgxpool.Pool, em audit.Emitter, actor, profile, version string) (Seeded, error) {
	s := Seeded{Profile: profile}
	var v *string
	if version != "" {
		v = &version
	}
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT seeded_version, package_digest, settings FROM posture.seed($1, $2)", profile, v).
			Scan(&s.Version, &s.Digest, &s.Settings); err != nil {
			return fmt.Errorf("seed: %w", err)
		}
		return em.Emit(ctx, audit.Event{
			Type:     "posture.seeded",
			Severity: audit.SeverityHigh,
			Actor:    actor,
			Target:   "profile:" + s.Profile + "@" + s.Version,
			Attributes: map[string]string{
				"profile": s.Profile, "version": s.Version, "package_digest": s.Digest, "settings": strconv.Itoa(s.Settings),
			},
		})
	})
	return s, err
}

// Imported is one package's import outcome: "imported" or "unchanged".
type Imported struct {
	Profile, Version, Digest, Outcome string
}

// Import loads a signed release directory (files by name: manifest.json,
// the packages it pins, and a .sig for each) after verifying the manifest
// signature, each package's pin and signature, and each package's schema
// with the bundled public key (AC-05, offline). Unsigned or tampered input
// loads nothing. Each loaded package is audited inside the transaction.
func Import(ctx context.Context, pool *pgxpool.Pool, em audit.Emitter, pub *ecdsa.PublicKey, actor string, files map[string][]byte) ([]Imported, error) {
	pkgs, err := profilepkg.VerifyRelease(pub, ManifestFile, files)
	if err != nil {
		return nil, fmt.Errorf("import refused: %w", err)
	}
	var out []Imported
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		out = out[:0]
		for _, p := range pkgs {
			b := files[profilepkg.FileName(p.Profile.ID, p.Profile.Version)]
			r := Imported{Profile: p.Profile.ID, Version: p.Profile.Version, Digest: profilepkg.Digest(b)}
			if err := tx.QueryRow(ctx, "SELECT posture.import_package($1)", b).Scan(&r.Outcome); err != nil {
				return fmt.Errorf("import %s %s: %w", r.Profile, r.Version, err)
			}
			if r.Outcome == "imported" {
				if err := em.Emit(ctx, audit.Event{
					Type:       "posture.package_imported",
					Severity:   audit.SeverityHigh,
					Actor:      actor,
					Target:     "profile:" + r.Profile + "@" + r.Version,
					Attributes: map[string]string{"profile": r.Profile, "version": r.Version, "package_digest": r.Digest},
				}); err != nil {
					return err
				}
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
