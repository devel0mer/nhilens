package version

import "fmt"

// These variables are populated at build time via -ldflags.
var (
	Version = "0.0.0-dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a human-readable version line.
func String() string {
	return fmt.Sprintf("nhilens %s (commit: %s, built: %s)", Version, Commit, Date)
}
