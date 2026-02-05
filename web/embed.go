// Package web provides embedded static files for the terminal landing page.
package web

import "embed"

// StaticFiles holds the embedded static web assets.
// The embed directive embeds the entire static/ directory.
//
//go:embed static
var StaticFiles embed.FS
