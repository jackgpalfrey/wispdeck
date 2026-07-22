package wispist

import (
	"testing"
	"time"
)

func TestRequestLimiterIsAtomicAcrossBuckets(t *testing.T) {
	t.Parallel()
	limits := DefaultRateLimits()
	limits.MutationBurst = 1
	limits.MutationsPerMinute = 1
	limiter := newRequestLimiter(limits)
	binding := Binding{StoreKey: "site", ClientKey: "client"}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	if allowed, _ := limiter.allow(binding, true, false, now); !allowed {
		t.Fatal("first mutation denied")
	}
	if allowed, retry := limiter.allow(binding, true, false, now); allowed || retry < time.Minute {
		t.Fatalf("second mutation = allowed %v, retry %s", allowed, retry)
	}
	if allowed, _ := limiter.allow(Binding{StoreKey: "other", ClientKey: "client"}, true, false, now); !allowed {
		t.Fatal("independent site/client mutation denied")
	}
}

func TestRequestLimiterBoundsConcurrentStreams(t *testing.T) {
	t.Parallel()
	limits := DefaultRateLimits()
	limits.SSEPerClientSite = 1
	limits.SSEPerSite = 2
	limiter := newRequestLimiter(limits)
	binding := Binding{StoreKey: "site", ClientKey: "one"}
	release, ok := limiter.acquireStream(binding)
	if !ok {
		t.Fatal("first stream denied")
	}
	if _, ok := limiter.acquireStream(binding); ok {
		t.Fatal("second stream for same client accepted")
	}
	release()
	if releaseAgain, ok := limiter.acquireStream(binding); !ok {
		t.Fatal("stream slot was not released")
	} else {
		releaseAgain()
	}
}
