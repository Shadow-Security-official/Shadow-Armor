// Package shadowarmor embeds the audit profile and the hardening cookbook so
// the sdw-armor binary is self-contained: nothing to download at run time.
package shadowarmor

import "embed"

// Profile is the CINC Auditor / InSpec profile (controls, effective-state
// resources and the catalog that maps every control to its standards).
//
//go:embed all:profile
var Profile embed.FS

// Cookbook is the Chef cookbook that converges declarative remediations.
//
//go:embed all:cookbook
var Cookbook embed.FS
