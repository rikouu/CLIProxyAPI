package executor

// claude_ratelimit.go — per-account RPM limiter, concurrency semaphore, and request jitter.
//
// Configuration is read from auth Attributes (set by the synthesizer from auth JSON files):
//
//   "rpm"             — maximum requests per minute for this account (e.g. "30")
//   "max_concurrency" — maximum simultaneous in-flight requests (e.g. "3")
//   "min_interval_ms" — minimum milliseconds between requests (e.g. "500")
//
// Example auth JSON:
//   {
//     "type": "claude",
//     "email": "user@example.com",
//     "access_token": "...",
//     "rpm": 30,
//     "max_concurrency": 2,
//     "min_interval_ms": 1000
//   }

import (
	"context"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// ─── Per-account state ────────────────────────────────────────────────────────

type accountRateState struct {
	mu sync.Mutex

	// Concurrency semaphore: nil means unlimited.
	sem chan struct{}

	// RPM token bucket.
	rpm       int           // 0 = unlimited
	tokens    float64       // current tokens (float for sub-second precision)
	maxTokens float64       // = rpm (bucket capacity = 1 minute of tokens)
	lastFill  time.Time     // when tokens was last updated
	fillRate  float64       // tokens per nanosecond = rpm / 60e9

	// Minimum interval between requests (jitter floor).
	minIntervalMs int
	lastRequest   time.Time
}

var (
	accountRateMu    sync.Mutex
	accountRateTable = map[string]*accountRateState{}
)

func getAccountRateState(authID string, rpm, maxConcurrency, minIntervalMs int) *accountRateState {
	accountRateMu.Lock()
	defer accountRateMu.Unlock()

	s, ok := accountRateTable[authID]
	if !ok {
		s = &accountRateState{}
		accountRateTable[authID] = s
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// (Re)configure semaphore when maxConcurrency changes.
	if maxConcurrency > 0 {
		if s.sem == nil || cap(s.sem) != maxConcurrency {
			// Drain old semaphore to avoid leaks (best-effort).
			if s.sem != nil {
				for len(s.sem) > 0 {
					<-s.sem
				}
			}
			s.sem = make(chan struct{}, maxConcurrency)
		}
	} else {
		s.sem = nil
	}

	// (Re)configure token bucket when RPM changes.
	if rpm > 0 && rpm != s.rpm {
		s.rpm = rpm
		s.maxTokens = float64(rpm)
		s.tokens = float64(rpm) // start full
		s.fillRate = float64(rpm) / 60e9 // per nanosecond
		s.lastFill = time.Now()
	} else if rpm == 0 {
		s.rpm = 0
		s.tokens = 0
		s.fillRate = 0
	}

	s.minIntervalMs = minIntervalMs
	return s
}

// refillTokens adds tokens based on elapsed time (call with s.mu held).
func (s *accountRateState) refillTokens() {
	if s.rpm == 0 || s.fillRate == 0 {
		return
	}
	now := time.Now()
	elapsed := float64(now.Sub(s.lastFill).Nanoseconds())
	s.tokens += elapsed * s.fillRate
	if s.tokens > s.maxTokens {
		s.tokens = s.maxTokens
	}
	s.lastFill = now
}

// ─── Public API ───────────────────────────────────────────────────────────────

// claudeRateLimitAttrs parses rate-limit attributes from an auth object.
func claudeRateLimitAttrs(auth *cliproxyauth.Auth) (rpm, maxConcurrency, minIntervalMs int) {
	if auth == nil || auth.Attributes == nil {
		return 0, 0, 0
	}
	attrs := auth.Attributes

	parseInt := func(keys ...string) int {
		for _, k := range keys {
			if v := strings.TrimSpace(attrs[k]); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					return n
				}
			}
		}
		return 0
	}

	// Also check Metadata for direct JSON fields (e.g. {"rpm": 30})
	parseMeta := func(key string, fallback int) int {
		if fallback > 0 {
			return fallback
		}
		if auth.Metadata != nil {
			switch v := auth.Metadata[key].(type) {
			case float64:
				if v > 0 {
					return int(v)
				}
			case int:
				if v > 0 {
					return v
				}
			case string:
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
					return n
				}
			}
		}
		return 0
	}

	rpm = parseMeta("rpm", parseInt("rpm", "rate_limit_rpm", "requests_per_minute"))
	maxConcurrency = parseMeta("max_concurrency", parseInt("max_concurrency", "concurrency", "max_concurrent"))
	minIntervalMs = parseMeta("min_interval_ms", parseInt("min_interval_ms", "min_interval", "request_interval_ms"))
	return
}

// AcquireClaudeSlot blocks until the account's rate limits allow a new request,
// then acquires the concurrency slot. Returns a release function that MUST be
// deferred by the caller.
//
// Returns ctx.Err() if the context is cancelled while waiting.
func AcquireClaudeSlot(ctx context.Context, auth *cliproxyauth.Auth) (release func(), err error) {
	if auth == nil {
		return func() {}, nil
	}

	rpm, maxConcurrency, minIntervalMs := claudeRateLimitAttrs(auth)

	// Fast path: nothing configured.
	if rpm == 0 && maxConcurrency == 0 && minIntervalMs == 0 {
		return func() {}, nil
	}

	s := getAccountRateState(auth.ID, rpm, maxConcurrency, minIntervalMs)

	// ── 1. Minimum interval / jitter ─────────────────────────────────────────
	if minIntervalMs > 0 {
		s.mu.Lock()
		since := time.Since(s.lastRequest)
		wait := time.Duration(minIntervalMs)*time.Millisecond - since
		// Add ±20% random jitter on top of the configured minimum.
		if wait > 0 {
			jitter := time.Duration(rand.Int63n(int64(minIntervalMs/5)+1)) * time.Millisecond
			wait += jitter
		} else {
			// Even when no forced wait, add a small random jitter (0–500 ms).
			wait = time.Duration(rand.Int63n(500)) * time.Millisecond
		}
		s.mu.Unlock()

		if wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return func() {}, ctx.Err()
			}
		}
	}

	// ── 2. RPM token bucket ───────────────────────────────────────────────────
	if rpm > 0 {
		for {
			s.mu.Lock()
			s.refillTokens()
			if s.tokens >= 1 {
				s.tokens--
				s.mu.Unlock()
				break
			}
			// Calculate how long until next token arrives.
			needed := 1.0 - s.tokens
			waitNs := needed / s.fillRate
			waitDur := time.Duration(waitNs) * time.Nanosecond
			if waitDur < time.Millisecond {
				waitDur = time.Millisecond
			}
			if waitDur > 5*time.Second {
				waitDur = 5 * time.Second
			}
			s.mu.Unlock()

			log.Debugf("[claude_ratelimit] auth=%s RPM=%d, waiting %v for token", auth.ID, rpm, waitDur.Round(time.Millisecond))
			select {
			case <-time.After(waitDur):
			case <-ctx.Done():
				return func() {}, ctx.Err()
			}
		}
	}

	// ── 3. Concurrency semaphore ──────────────────────────────────────────────
	if s.sem != nil {
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			return func() {}, ctx.Err()
		}
	}

	// Mark request time.
	s.mu.Lock()
	s.lastRequest = time.Now()
	s.mu.Unlock()

	// Release function: frees the concurrency slot.
	return func() {
		if s.sem != nil {
			<-s.sem
		}
	}, nil
}
