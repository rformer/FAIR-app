// Package profiles embeds the release's profile packages (F-015 T-10).
// `iam migrate` loads them into the database through posture.sync_packages;
// their integrity comes from the signed binary, and each is checked against
// the digest pinned in packages/manifest.json before loading.
package profiles

import "embed"

// Packages holds packages/manifest.json and the packages it pins.
//
//go:embed packages/*.json
var Packages embed.FS
