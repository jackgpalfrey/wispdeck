package limit

import (
	"testing"
	"time"
)

func TestLoginLimiterUsesIndependentKeys(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	limiter := NewLoginLimiter()
	limiter.now = func() time.Time { return now }
	limiter.userLimit = 2
	limiter.addressLimit = 3

	if !limiter.Allow("alice", "192.0.2.1") || !limiter.Allow("alice", "192.0.2.2") {
		t.Fatal("initial username attempts were rejected")
	}
	if limiter.Allow("alice", "192.0.2.3") {
		t.Fatal("distributed attempts bypassed username limit")
	}
	if !limiter.Allow("bob", "192.0.2.4") || !limiter.Allow("carol", "192.0.2.4") || !limiter.Allow("dave", "192.0.2.4") {
		t.Fatal("initial address attempts were rejected")
	}
	if limiter.Allow("erin", "192.0.2.4") {
		t.Fatal("multiple usernames bypassed address limit")
	}

	now = now.Add(time.Minute + time.Nanosecond)
	if !limiter.Allow("alice", "192.0.2.4") {
		t.Fatal("expired attempts were not removed")
	}
}
