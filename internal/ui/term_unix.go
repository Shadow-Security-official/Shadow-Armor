//go:build linux || darwin || freebsd || netbsd || openbsd

package ui

import (
	"os"
	"syscall"
	"unsafe"
)

type winsize struct {
	Row, Col, X, Y uint16
}

// termWidth asks the terminal behind f for its width (0 when unknown).
func termWidth(f *os.File) int {
	var ws winsize
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws))) //nolint:gosec // TIOCGWINSZ fills a winsize struct
	if errno != 0 {
		return 0
	}
	return int(ws.Col)
}
