package model

import "embed"

// SchemaFiles are the published JSON Schemas (2020-12) of the document
// kinds, for integrators and the export format (design §3.3, §6.5).
//
//go:embed schema/*.json
var SchemaFiles embed.FS

// SchemaRef is the schema location of a document kind, resolvable once
// every file in SchemaFiles is loaded under its $id.
func SchemaRef(kind string) string {
	if kind == KindScenario {
		return "urn:fair:risk:scenario:1"
	}
	return "urn:fair:risk:library:1#/$defs/" + kind
}
