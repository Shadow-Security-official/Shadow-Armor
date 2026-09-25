//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package ui

import "os"

func termWidth(*os.File) int { return 0 }
