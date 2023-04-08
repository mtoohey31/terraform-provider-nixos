package version

import (
	_ "embed"
)

// Version is the current version of this program.
//
//go:embed version.txt
var Version string
