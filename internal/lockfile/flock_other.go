//go:build !darwin && !linux && !freebsd && !netbsd && !openbsd

package lockfile

import "os"

// flock reports that this platform cannot lock, rather than pretending it can.
//
// Returning success here would be the worst available answer: every process
// would believe it held an exclusive lock, and the concurrent writes the
// package exists to prevent would proceed while looking protected. The caller
// sees ErrUnsupported and decides — for ndscan that means recording the scan
// anyway, which is exactly the behaviour these platforms already had.
func flock(f *os.File) error   { return ErrUnsupported }
func funlock(f *os.File) error { return nil }
