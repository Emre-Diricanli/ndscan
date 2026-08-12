//go:build darwin || linux || freebsd || netbsd || openbsd

package lockfile

import (
	"os"
	"syscall"
)

// flock takes the exclusive lock without blocking.
//
// stdlib syscall rather than golang.org/x/sys: that module is present only as
// an indirect dependency, and promoting it to a direct one for a single call
// available in the standard library is not a trade worth making.
func flock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func funlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
