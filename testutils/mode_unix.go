//go:build linux || darwin
// +build linux darwin

package testutils

import (
	"os"
)

// reference: os package
var MaskChmod = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
