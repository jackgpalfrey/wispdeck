package wispist

import (
	"math"
	"sync"
	"time"
)

type bucketKey struct {
	kind   uint8
	store  string
	client string
}

type tokenBucket struct {
	tokens  float64
	updated time.Time
	used    time.Time
}

type bucketRequest struct {
	key       bucketKey
	perSecond float64
	burst     float64
}

type requestLimiter struct {
	mu            sync.Mutex
	limits        RateLimits
	buckets       map[bucketKey]*tokenBucket
	siteStreams   map[string]int
	clientStreams map[bucketKey]int
	lastPrune     time.Time
}

func newRequestLimiter(limits RateLimits) *requestLimiter {
	return &requestLimiter{
		limits: limits, buckets: make(map[bucketKey]*tokenBucket),
		siteStreams: make(map[string]int), clientStreams: make(map[bucketKey]int),
	}
}

func (l *requestLimiter) allow(binding Binding, mutation, generated bool, now time.Time) (bool, time.Duration) {
	requests := []bucketRequest{{
		key:       bucketKey{kind: 1},
		perSecond: float64(l.limits.InstallationRequestsMinute) / 60,
		burst:     float64(l.limits.InstallationRequestBurst),
	}}
	if mutation {
		requests = append(requests,
			bucketRequest{
				key:       bucketKey{kind: 3, store: binding.StoreKey, client: binding.ClientKey},
				perSecond: float64(l.limits.MutationsPerMinute) / 60,
				burst:     float64(l.limits.MutationBurst),
			},
			bucketRequest{
				key:       bucketKey{kind: 4, store: binding.StoreKey},
				perSecond: float64(l.limits.SiteMutationsPerMinute) / 60,
				burst:     float64(l.limits.SiteMutationBurst),
			},
		)
	} else {
		requests = append(requests, bucketRequest{
			key:       bucketKey{kind: 2, store: binding.StoreKey, client: binding.ClientKey},
			perSecond: float64(l.limits.ReadsPerMinute) / 60,
			burst:     float64(l.limits.ReadBurst),
		})
	}
	if generated {
		requests = append(requests, bucketRequest{
			key:       bucketKey{kind: 5, store: binding.StoreKey},
			perSecond: float64(l.limits.GeneratedDocumentsPerDay) / (24 * 60 * 60),
			burst:     float64(l.limits.GeneratedDocumentBurst),
		})
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	missing := 0
	for _, request := range requests {
		if _, ok := l.buckets[request.key]; !ok {
			missing++
		}
	}
	if len(l.buckets)+missing > l.limits.MaxBuckets {
		return false, time.Second
	}

	wait := time.Duration(0)
	for _, request := range requests {
		bucket := l.buckets[request.key]
		if bucket == nil {
			continue
		}
		refillBucket(bucket, request, now)
		if bucket.tokens < 1 {
			needed := time.Duration(math.Ceil((1 - bucket.tokens) / request.perSecond * float64(time.Second)))
			if needed > wait {
				wait = needed
			}
		}
	}
	if wait > 0 {
		return false, wait
	}
	for _, request := range requests {
		bucket := l.buckets[request.key]
		if bucket == nil {
			bucket = &tokenBucket{tokens: request.burst, updated: now}
			l.buckets[request.key] = bucket
		}
		refillBucket(bucket, request, now)
		bucket.tokens--
		bucket.used = now
	}
	return true, 0
}

func refillBucket(bucket *tokenBucket, request bucketRequest, now time.Time) {
	if now.After(bucket.updated) {
		bucket.tokens = math.Min(request.burst, bucket.tokens+now.Sub(bucket.updated).Seconds()*request.perSecond)
		bucket.updated = now
	}
}

func (l *requestLimiter) acquireStream(binding Binding) (func(), bool) {
	key := bucketKey{kind: 6, store: binding.StoreKey, client: binding.ClientKey}
	l.mu.Lock()
	if l.siteStreams[binding.StoreKey] >= l.limits.SSEPerSite || l.clientStreams[key] >= l.limits.SSEPerClientSite {
		l.mu.Unlock()
		return nil, false
	}
	l.siteStreams[binding.StoreKey]++
	l.clientStreams[key]++
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			l.siteStreams[binding.StoreKey]--
			if l.siteStreams[binding.StoreKey] == 0 {
				delete(l.siteStreams, binding.StoreKey)
			}
			l.clientStreams[key]--
			if l.clientStreams[key] == 0 {
				delete(l.clientStreams, key)
			}
			l.mu.Unlock()
		})
	}, true
}

func (l *requestLimiter) pruneLocked(now time.Time) {
	if !l.lastPrune.IsZero() && now.Sub(l.lastPrune) < time.Minute && len(l.buckets) < l.limits.MaxBuckets {
		return
	}
	for key, bucket := range l.buckets {
		if now.Sub(bucket.used) >= l.limits.BucketIdleTime {
			delete(l.buckets, key)
		}
	}
	l.lastPrune = now
}
