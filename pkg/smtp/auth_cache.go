package smtp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"migadu/mizu/pkg/concurrency"
	"sync"
	"sync/atomic"
	"time"
)

// AuthResult represents the result of an authentication attempt
type AuthResult int

const (
	AuthSuccess AuthResult = iota
	AuthFailed
	AuthUserNotFound
	AuthInvalidPassword
)

// AuthCacheEntry represents a cached authentication result
type AuthCacheEntry struct {
	// Authentication data
	PasswordHash string // SHA-256 hash of plaintext password for comparison

	// Metadata
	Result    AuthResult
	CreatedAt time.Time
	ExpiresAt time.Time
}

// AuthCache provides in-memory caching for authentication results
type AuthCache struct {
	mu              sync.RWMutex
	entries         map[string]*AuthCacheEntry
	positiveTTL     time.Duration
	negativeTTL     time.Duration
	maxSize         int
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	cleanupStopped  chan struct{}
	stopped         bool

	// Revalidation window for password change detection
	positiveRevalidationWindow time.Duration

	// Metrics
	hits   uint64
	misses uint64

	logger *slog.Logger
}

// NewAuthCache creates a new authentication cache instance
func NewAuthCache(positiveTTL, negativeTTL time.Duration, maxSize int, cleanupInterval time.Duration, positiveRevalidationWindow time.Duration, logger *slog.Logger) *AuthCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute
	}
	if positiveRevalidationWindow <= 0 {
		positiveRevalidationWindow = 30 * time.Second
	}

	cache := &AuthCache{
		entries:                    make(map[string]*AuthCacheEntry),
		positiveTTL:                positiveTTL,
		negativeTTL:                negativeTTL,
		maxSize:                    maxSize,
		cleanupInterval:            cleanupInterval,
		positiveRevalidationWindow: positiveRevalidationWindow,
		stopCleanup:                make(chan struct{}),
		cleanupStopped:             make(chan struct{}),
		logger:                     logger,
	}

	// Start background cleanup goroutine
	concurrency.SafeGo(logger, "auth-cache-cleanup", cache.cleanupLoop)

	return cache
}

// hashPassword creates a SHA-256 hash of the password for cache comparison.
// This is used to detect password changes without storing plaintext passwords in the cache.
func hashPassword(password string) string {
	if password == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// isOld checks if a cache entry is older than the given duration
func (e *AuthCacheEntry) isOld(duration time.Duration) bool {
	return time.Since(e.CreatedAt) > duration
}

// CheckAuth attempts to validate authentication using cached data
// Returns:
//   - (true, true) on cache hit with successful authentication
//   - (false, false) in every other case: not cached, expired, a negative
//     (failed-auth) entry, or a positive entry that needs (re)validation.
//     The caller must verify against the backend; brute-force protection is
//     the auth rate limiter's job, never the cache's.
//
// Uses password-aware revalidation to detect password changes while preventing rapid brute force attempts
func (c *AuthCache) CheckAuth(username, password string) (authenticated bool, found bool) {
	c.mu.RLock()
	entry, exists := c.entries[username]
	if !exists {
		c.mu.RUnlock()
		atomic.AddUint64(&c.misses, 1)
		return false, false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		c.mu.RUnlock()
		atomic.AddUint64(&c.misses, 1)
		return false, false
	}

	atomic.AddUint64(&c.hits, 1)

	// Hash the provided password for comparison
	passwordHash := hashPassword(password)

	// Check if password matches cached hash (constant-time comparison to prevent timing attacks)
	passwordMatches := entry.PasswordHash != "" &&
		subtle.ConstantTimeCompare([]byte(entry.PasswordHash), []byte(passwordHash)) == 1

	// Handle negative cache entries (failed authentication)
	if entry.Result != AuthSuccess {
		c.mu.RUnlock()
		// ALWAYS allow revalidation for negative entries, regardless of password match
		// This is critical because:
		// 1. User might not have existed when first cached, but could be created later
		// 2. User's password might have been wrong, but could be changed to match what they tried
		// 3. We rely on the negative TTL (typically 1 minute) to expire stale failures
		// 4. Brute force protection is handled by auth rate limiting
		c.logger.Debug("Auth cache: negative entry revalidation allowed",
			"username", username,
			"same_password", passwordMatches,
			"age", time.Since(entry.CreatedAt))
		return false, false
	}

	// Positive cache entry - successful authentication previously cached
	if passwordMatches {
		// Same password - check if entry is old enough to require revalidation
		if entry.isOld(c.positiveRevalidationWindow) {
			// Entry is old - revalidate to detect password changes
			c.mu.RUnlock()
			c.logger.Debug("Auth cache: positive entry revalidation needed (entry too old)",
				"username", username,
				"age", time.Since(entry.CreatedAt))
			return false, false
		}

		// Entry is fresh and password matches - return success
		c.mu.RUnlock()
		c.logger.Debug("Auth cache hit: successful authentication",
			"username", username,
			"age", time.Since(entry.CreatedAt))
		return true, true
	} else {
		// Different password on positive entry - ALWAYS allow revalidation
		// User might have changed their password, or they're trying a wrong password.
		// Either way, we need to check with the authenticator to verify.
		// Brute force protection is handled by auth rate limiting, not by the cache.
		c.mu.RUnlock()
		c.logger.Debug("Auth cache: positive entry revalidation allowed (different password)",
			"username", username,
			"age", time.Since(entry.CreatedAt))
		return false, false
	}
}

// SetSuccess caches a successful authentication result
func (c *AuthCache) SetSuccess(username, password string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Enforce max size with simple eviction (oldest entries first)
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	now := time.Now()
	c.entries[username] = &AuthCacheEntry{
		PasswordHash: hashPassword(password),
		Result:       AuthSuccess,
		CreatedAt:    now,
		ExpiresAt:    now.Add(c.positiveTTL),
	}

	c.logger.Debug("Auth cache: cached successful authentication",
		"username", username,
		"expires_in", c.positiveTTL)
}

// SetFailure caches a failed authentication result
func (c *AuthCache) SetFailure(username, password string, result AuthResult) {
	if result == AuthSuccess {
		return // Don't cache success as failure
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Enforce max size with simple eviction (oldest entries first)
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	now := time.Now()
	c.entries[username] = &AuthCacheEntry{
		PasswordHash: hashPassword(password),
		Result:       result,
		CreatedAt:    now,
		ExpiresAt:    now.Add(c.negativeTTL),
	}

	c.logger.Debug("Auth cache: cached failed authentication",
		"username", username,
		"result", result,
		"expires_in", c.negativeTTL)
}

// Invalidate removes a specific entry from the cache (e.g., after password change)
func (c *AuthCache) Invalidate(username string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, username)
	c.logger.Debug("Auth cache: invalidated entry", "username", username)
}

// evictOldest removes the oldest entry from the cache
// Caller must hold the write lock
func (c *AuthCache) evictOldest() {
	if len(c.entries) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range c.entries {
		if first || entry.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.ExpiresAt
			first = false
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// cleanupLoop periodically removes expired entries
func (c *AuthCache) cleanupLoop() {
	defer close(c.cleanupStopped)

	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCleanup:
			return
		}
	}
}

// cleanup removes expired entries
func (c *AuthCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
			removed++
		}
	}

	if removed > 0 {
		c.logger.Info("Auth cache cleanup removed expired entries",
			"removed", removed,
			"remaining", len(c.entries))
	}

	// Calculate positive vs negative entry counts
	successEntries := 0
	failedEntries := 0
	for _, entry := range c.entries {
		if entry.Result == AuthSuccess {
			successEntries++
		} else {
			failedEntries++
		}
	}

	// Log stats
	hits := atomic.LoadUint64(&c.hits)
	misses := atomic.LoadUint64(&c.misses)
	total := hits + misses
	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	c.logger.Debug("Auth cache stats",
		"total_entries", len(c.entries),
		"success_entries", successEntries,
		"failed_entries", failedEntries,
		"max_size", c.maxSize,
		"hit_rate_pct", hitRate,
		"hits", hits,
		"misses", misses)
}

// Stop stops the cleanup goroutine
func (c *AuthCache) Stop(ctx context.Context) error {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return nil // Already stopped
	}
	c.stopped = true
	c.mu.Unlock()

	close(c.stopCleanup)

	// Wait for cleanup to stop with timeout
	select {
	case <-c.cleanupStopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetStats returns cache statistics
func (c *AuthCache) GetStats() (hits, misses uint64, size int, hitRate float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hits = atomic.LoadUint64(&c.hits)
	misses = atomic.LoadUint64(&c.misses)
	total := hits + misses
	var rate float64
	if total > 0 {
		rate = float64(hits) / float64(total) * 100
	}

	return hits, misses, len(c.entries), rate
}

// Clear removes all entries from the cache
func (c *AuthCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*AuthCacheEntry)
	atomic.StoreUint64(&c.hits, 0)
	atomic.StoreUint64(&c.misses, 0)

	c.logger.Info("Auth cache cleared")
}
