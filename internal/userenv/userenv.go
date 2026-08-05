// Package userenv preserves the invoking user's home and file ownership when
// ndscan has relaunched itself as root.
package userenv

import (
	"os"
	"strconv"
)

func Home() string {
	if home := os.Getenv("NDSCAN_USER_HOME"); home != "" {
		return home
	}
	home, _ := os.UserHomeDir()
	return home
}

// Chown gives a generated path back to the user who launched ndscan. It is a
// no-op when ndscan was started directly as root or ownership is unavailable.
func Chown(path string) error {
	uid, uidErr := strconv.Atoi(os.Getenv("NDSCAN_USER_UID"))
	gid, gidErr := strconv.Atoi(os.Getenv("NDSCAN_USER_GID"))
	if uidErr != nil || gidErr != nil {
		return nil
	}
	return os.Chown(path, uid, gid)
}
