// Package migrations embeds the forward-only SQL migrations.
// Files are named NNNN_description.sql and applied in numeric order.
package migrations

import "embed"

// FS holds every migration file.
//
//go:embed *.sql
var FS embed.FS
