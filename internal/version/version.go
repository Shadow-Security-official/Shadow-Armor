// Package version is stamped at build time with -ldflags -X.
package version

var (
	// Version of sdw-armor (set by the release build).
	Version = "0.5.0-dev"
	// Commit the binary was built from.
	Commit = ""
	// Date of the build (RFC 3339).
	Date = ""
)
