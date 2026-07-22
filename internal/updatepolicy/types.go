// Package updatepolicy contains durable, provider-independent update settings
// and audit records shared by the updater and control database.
package updatepolicy

import "time"

type Mode string

const (
	ModeNotify    Mode = "notify"
	ModeAutomatic Mode = "automatic"
	ModeDisabled  Mode = "disabled"
)

func ValidMode(mode Mode) bool {
	return mode == ModeNotify || mode == ModeAutomatic || mode == ModeDisabled
}

type Settings struct {
	Mode           Mode
	SkippedVersion string
	UpdatedAt      time.Time
}

type Actor struct {
	UserID   string
	Username string
	ClientIP string
}

type Event struct {
	OccurredAt time.Time
	Actor      Actor
	Kind       string
	Version    string
	Details    string
}
