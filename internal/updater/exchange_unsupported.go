//go:build !linux

package updater

import "errors"

func exchangeFiles(_, _ string) error {
	return errors.New("atomic update activation is supported only on Linux")
}
