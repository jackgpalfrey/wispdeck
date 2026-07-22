// Package updater implements Wispdeck's signed, stable-release update path.
package updater

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Version struct {
	Major uint64
	Minor uint64
	Patch uint64
}

func ParseVersion(value string) (Version, error) {
	if !strings.HasPrefix(value, "v") || strings.ContainsAny(value, "+-") {
		return Version{}, errors.New("version must be a stable vMAJOR.MINOR.PATCH tag")
	}
	parts := strings.Split(strings.TrimPrefix(value, "v"), ".")
	if len(parts) != 3 {
		return Version{}, errors.New("version must be a stable vMAJOR.MINOR.PATCH tag")
	}
	values := make([]uint64, 3)
	for index, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return Version{}, errors.New("version components must be canonical decimal integers")
		}
		for _, char := range []byte(part) {
			if char < '0' || char > '9' {
				return Version{}, errors.New("version components must be decimal integers")
			}
		}
		parsed, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return Version{}, fmt.Errorf("parse version component: %w", err)
		}
		values[index] = parsed
	}
	return Version{Major: values[0], Minor: values[1], Patch: values[2]}, nil
}

func (v Version) Compare(other Version) int {
	for _, pair := range [][2]uint64{{v.Major, other.Major}, {v.Minor, other.Minor}, {v.Patch, other.Patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	return 0
}

func (v Version) String() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}
