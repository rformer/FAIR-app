// Package db embeds the schema migrations so the binary carries exactly the
// migrations it was built and tested with (F-001 T-02b).
package db

import "embed"

// Migrations holds migrations/NNNN_name.sql, applied in lexical order.
//
//go:embed migrations/*.sql
var Migrations embed.FS
