// Package oscalpin carries the pinned OSCAL JSON schema (F-015 T-01).
//
// MANIFEST.json records the source URL and SHA-256 of every pinned file in
// this directory (fetch.sh writes it); tests verify the digests. Only the
// schema and manifest are embedded; the NIST content files are read from
// disk by tests and by the build-time profilegen tool.
package oscalpin

import _ "embed"

// CompleteSchema is the OSCAL complete JSON schema at the pinned version.
//
//go:embed schemas/oscal_complete_schema.json
var CompleteSchema []byte

// Manifest lists the pinned files with their sources and SHA-256 digests.
//
//go:embed MANIFEST.json
var Manifest []byte
