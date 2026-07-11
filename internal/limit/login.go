// Package limit provides bounded abuse controls for public endpoints.
package limit

import (
	"sync"
	"time"
)

type window struct {
	attempts []time.Time
	seenAt   time.Time
}

// LoginLimiter applies independent sliding-window limits to usernames and
// client addresses. State is deliberately process-local: Wispdeck v1 is a
// single-process application.
type LoginLimiter struct {
	mu           sync.Mutex
	now          func() time.Time
	period       time.Duration
	userLimit    int
	addressLimit int
	maxKeys      int
	users        map[string]*window
	addresses    map[string]*window
}

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{
		now:          time.Now,
		period:       time.Minute,
		userLimit:    5,
		addressLimit: 20,
		maxKeys:      10_000,
		users:        make(map[string]*window),
		addresses:    make(map[string]*window),
	}
}

// Allow records an attempt and reports whether both independent limits permit
// it. Unknown usernames are included so the limiter does not reveal accounts.
func (l *LoginLimiter) Allow(username, address string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.pruneIfNeeded(now)
	userAllowed := record(l.users, username, now, l.period, l.userLimit, l.maxKeys)
	addressAllowed := record(l.addresses, address, now, l.period, l.addressLimit, l.maxKeys)
	return userAllowed && addressAllowed
}

func record(windows map[string]*window, key string, now time.Time, period time.Duration, maximum, maxKeys int) bool {
	w, ok := windows[key]
	if !ok {
		if len(windows) >= maxKeys {
			return false
		}
		w = &window{}
		windows[key] = w
	}
	cutoff := now.Add(-period)
	first := 0
	for first < len(w.attempts) && !w.attempts[first].After(cutoff) {
		first++
	}
	w.attempts = append(w.attempts[first:], now)
	w.seenAt = now
	return len(w.attempts) <= maximum
}

func (l *LoginLimiter) pruneIfNeeded(now time.Time) {
	if len(l.users)+len(l.addresses) < l.maxKeys {
		return
	}
	cutoff := now.Add(-l.period)
	prune := func(windows map[string]*window) {
		for key, w := range windows {
			if !w.seenAt.After(cutoff) {
				delete(windows, key)
			}
		}
	}
	prune(l.users)
	prune(l.addresses)
}
