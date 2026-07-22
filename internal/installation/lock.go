// Package installation owns offline operations across Wispdeck's control
// database, authentication key, and Wispist data directory.
package installation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var ErrInUse = errors.New("Wispdeck installation state is in use")

type Lock struct {
	file *os.File
}

// AcquireLock takes a process-wide advisory lock associated with the control
// database. The serving process holds it for its full lifetime; offline
// maintenance commands fail closed when it is already held.
func AcquireLock(databasePath string) (*Lock, error) {
	if databasePath == "" || databasePath == ":memory:" {
		return nil, errors.New("a filesystem control database is required")
	}
	path, err := filepath.Abs(filepath.Clean(databasePath) + ".lock")
	if err != nil {
		return nil, fmt.Errorf("resolve installation lock path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create installation lock directory: %w", err)
	}
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open installation lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open installation lock: invalid file descriptor")
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("restrict installation lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrInUse
		}
		return nil, fmt.Errorf("lock installation state: %w", err)
	}
	return &Lock{file: file}, nil
}

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(unlockErr, closeErr)
}
