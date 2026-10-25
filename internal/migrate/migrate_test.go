package migrate_test

import (
	"errors"
	"testing"
	"testing/fstest"

	"github.com/rformer/fair-app/internal/migrate"
	"github.com/rformer/fair-app/migrations"
)

func TestEmbeddedMigrationsLoad(t *testing.T) {
	ms, err := migrate.Load(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 || ms[0].Version != 1 || ms[0].Checksum == "" {
		t.Fatalf("unexpected %+v", ms)
	}
}

func TestLoadRejectsGapsAndBadNames(t *testing.T) {
	gap := fstest.MapFS{
		"0001_a.sql": {Data: []byte("select 1")},
		"0003_c.sql": {Data: []byte("select 1")},
	}
	if _, err := migrate.Load(gap); err == nil {
		t.Fatal("expected gap error")
	}
	bad := fstest.MapFS{"1_a.sql": {Data: []byte("select 1")}}
	if _, err := migrate.Load(bad); !errors.Is(err, migrate.ErrBadFileName) {
		t.Fatalf("got %v", err)
	}
}
