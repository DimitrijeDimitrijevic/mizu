package smtp

import (
	"context"
	"testing"
	"time"

	"migadu/mizu/pkg/logging"
)

// TestAuthCache_PositiveCaching tests successful authentication caching
func TestAuthCache_PositiveCaching(t *testing.T) {
	logger := logging.NewTestLogger()
	cache := NewAuthCache(5*time.Minute, 1*time.Minute, 100, 1*time.Hour, 30*time.Second, logger)
	defer cache.Stop(context.Background())

	username := "user@example.com"
	password := "correct-password"

	// First check - cache miss
	authenticated, found := cache.CheckAuth(username, password)
	if found {
		t.Error("Expected cache miss on first check")
	}

	// Cache a successful authentication
	cache.SetSuccess(username, password)

	// Second check - cache hit
	authenticated, found = cache.CheckAuth(username, password)
	if !found || !authenticated {
		t.Error("Expected cache hit with successful authentication")
	}

	t.Logf("✓ Positive caching working correctly")
}

// TestAuthCache_NegativeCaching tests failed authentication caching
func TestAuthCache_NegativeCaching(t *testing.T) {
	logger := logging.NewTestLogger()
	cache := NewAuthCache(5*time.Minute, 1*time.Minute, 100, 1*time.Hour, 30*time.Second, logger)
	defer cache.Stop(context.Background())

	username := "user@example.com"
	password := "wrong-password"

	// Cache a failed authentication
	cache.SetFailure(username, password, AuthInvalidPassword)

	// Check - should indicate cached failure (found=false to trigger revalidation)
	authenticated, found := cache.CheckAuth(username, password)
	if authenticated || found {
		t.Errorf("Expected negative cache to allow revalidation, got authenticated=%v, found=%v",
			authenticated, found)
	}

	t.Logf("✓ Negative caching working correctly")
}

// TestAuthCache_PasswordChange tests password change detection
func TestAuthCache_PasswordChange(t *testing.T) {
	logger := logging.NewTestLogger()
	cache := NewAuthCache(5*time.Minute, 1*time.Minute, 100, 1*time.Hour, 30*time.Second, logger)
	defer cache.Stop(context.Background())

	username := "user@example.com"
	password1 := "old-password"
	password2 := "new-password"

	// Cache successful auth with password1
	cache.SetSuccess(username, password1)

	// Check with password1 - should succeed
	authenticated, found := cache.CheckAuth(username, password1)
	if !found || !authenticated {
		t.Error("Expected cache hit with correct password")
	}

	// Check with password2 (different password) - should trigger revalidation
	authenticated, found = cache.CheckAuth(username, password2)
	if authenticated || found {
		t.Error("Expected password change to trigger revalidation")
	}

	t.Logf("✓ Password change detection working correctly")
}

// TestAuthCache_PositiveRevalidation tests revalidation window for successful auth
func TestAuthCache_PositiveRevalidation(t *testing.T) {
	logger := logging.NewTestLogger()
	// Short revalidation window for testing
	cache := NewAuthCache(5*time.Minute, 1*time.Minute, 100, 1*time.Hour, 50*time.Millisecond, logger)
	defer cache.Stop(context.Background())

	username := "user@example.com"
	password := "correct-password"

	// Cache successful auth
	cache.SetSuccess(username, password)

	// Immediate check - should use cache
	authenticated, found := cache.CheckAuth(username, password)
	if !found || !authenticated {
		t.Error("Expected cache hit immediately after caching")
	}

	// Wait for revalidation window to expire
	time.Sleep(60 * time.Millisecond)

	// Check again - should trigger revalidation due to age
	authenticated, found = cache.CheckAuth(username, password)
	if authenticated || found {
		t.Error("Expected revalidation after revalidation window expires")
	}

	t.Logf("✓ Positive revalidation window working correctly")
}

// TestAuthCache_TTLExpiration tests cache entry expiration
func TestAuthCache_TTLExpiration(t *testing.T) {
	logger := logging.NewTestLogger()
	// Short TTLs for testing
	cache := NewAuthCache(100*time.Millisecond, 100*time.Millisecond, 100, 1*time.Hour, 30*time.Second, logger)
	defer cache.Stop(context.Background())

	username := "user@example.com"
	password := "correct-password"

	// Cache successful auth
	cache.SetSuccess(username, password)

	// Immediate check - should hit cache
	_, found := cache.CheckAuth(username, password)
	if !found {
		t.Error("Expected cache hit immediately")
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Check again - should miss (expired)
	_, found = cache.CheckAuth(username, password)
	if found {
		t.Error("Expected cache miss after TTL expiration")
	}

	t.Logf("✓ TTL expiration working correctly")
}

// TestAuthCache_SizeLimit tests max size enforcement with LRU eviction
func TestAuthCache_SizeLimit(t *testing.T) {
	logger := logging.NewTestLogger()
	cache := NewAuthCache(5*time.Minute, 1*time.Minute, 5, 1*time.Hour, 30*time.Second, logger)
	defer cache.Stop(context.Background())

	// Add 5 entries (at limit)
	for i := 1; i <= 5; i++ {
		username := "user" + string(rune('0'+i)) + "@example.com"
		cache.SetSuccess(username, "password")
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	// Verify we have 5 entries
	hits, misses, size, _ := cache.GetStats()
	if size != 5 {
		t.Fatalf("Expected 5 entries, got %d", size)
	}

	// Add 6th entry - should evict oldest (user1)
	cache.SetSuccess("user6@example.com", "password")

	// Should still have 5 entries
	hits, misses, size, _ = cache.GetStats()
	if size != 5 {
		t.Errorf("Expected 5 entries after eviction, got %d", size)
	}

	// user1 should be evicted (cache miss)
	_, found := cache.CheckAuth("user1@example.com", "password")
	if found {
		t.Error("user1 should have been evicted (oldest entry)")
	}

	// user6 should exist (cache hit)
	_, found = cache.CheckAuth("user6@example.com", "password")
	if !found {
		t.Error("user6 should exist (newest entry)")
	}

	t.Logf("✓ LRU eviction working correctly (stats: hits=%d, misses=%d, size=%d)", hits, misses, size)
}

// TestAuthCache_Cleanup tests periodic cleanup of expired entries
func TestAuthCache_Cleanup(t *testing.T) {
	logger := logging.NewTestLogger()
	// Short TTL and cleanup interval for testing
	cache := NewAuthCache(50*time.Millisecond, 50*time.Millisecond, 100, 100*time.Millisecond, 30*time.Second, logger)
	defer cache.Stop(context.Background())

	// Add some entries
	for i := 1; i <= 3; i++ {
		username := "user" + string(rune('0'+i)) + "@example.com"
		cache.SetSuccess(username, "password")
	}

	// Verify entries exist
	_, _, size, _ := cache.GetStats()
	if size != 3 {
		t.Fatalf("Expected 3 entries, got %d", size)
	}

	// Wait for entries to expire and cleanup to run
	time.Sleep(200 * time.Millisecond)

	// Should be cleaned up
	_, _, size, _ = cache.GetStats()
	if size != 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d", size)
	}

	t.Logf("✓ Cleanup working correctly")
}

// TestAuthCache_Invalidate tests manual cache invalidation
func TestAuthCache_Invalidate(t *testing.T) {
	logger := logging.NewTestLogger()
	cache := NewAuthCache(5*time.Minute, 1*time.Minute, 100, 1*time.Hour, 30*time.Second, logger)
	defer cache.Stop(context.Background())

	username := "user@example.com"
	password := "correct-password"

	// Cache successful auth
	cache.SetSuccess(username, password)

	// Verify cached
	_, found := cache.CheckAuth(username, password)
	if !found {
		t.Error("Expected cache hit")
	}

	// Invalidate
	cache.Invalidate(username)

	// Should be gone
	_, found = cache.CheckAuth(username, password)
	if found {
		t.Error("Expected cache miss after invalidation")
	}

	t.Logf("✓ Manual invalidation working correctly")
}

// TestAuthCache_Clear tests clearing entire cache
func TestAuthCache_Clear(t *testing.T) {
	logger := logging.NewTestLogger()
	cache := NewAuthCache(5*time.Minute, 1*time.Minute, 100, 1*time.Hour, 30*time.Second, logger)
	defer cache.Stop(context.Background())

	// Add several entries
	for i := 1; i <= 5; i++ {
		username := "user" + string(rune('0'+i)) + "@example.com"
		cache.SetSuccess(username, "password")
	}

	// Verify entries exist
	_, _, size, _ := cache.GetStats()
	if size != 5 {
		t.Fatalf("Expected 5 entries, got %d", size)
	}

	// Clear cache
	cache.Clear()

	// Should be empty
	_, _, size, _ = cache.GetStats()
	if size != 0 {
		t.Errorf("Expected 0 entries after clear, got %d", size)
	}

	t.Logf("✓ Clear working correctly")
}

// TestAuthCache_HitRateStats tests statistics collection
func TestAuthCache_HitRateStats(t *testing.T) {
	logger := logging.NewTestLogger()
	cache := NewAuthCache(5*time.Minute, 1*time.Minute, 100, 1*time.Hour, 30*time.Second, logger)
	defer cache.Stop(context.Background())

	username := "user@example.com"
	password := "correct-password"

	// First check - miss
	cache.CheckAuth(username, password)

	// Cache it
	cache.SetSuccess(username, password)

	// Three hits
	cache.CheckAuth(username, password)
	cache.CheckAuth(username, password)
	cache.CheckAuth(username, password)

	// Get stats
	hits, misses, size, hitRate := cache.GetStats()

	if hits != 3 {
		t.Errorf("Expected 3 hits, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("Expected 1 miss, got %d", misses)
	}
	if size != 1 {
		t.Errorf("Expected 1 entry, got %d", size)
	}

	expectedHitRate := 75.0 // 3/(3+1) * 100
	if hitRate < expectedHitRate-0.1 || hitRate > expectedHitRate+0.1 {
		t.Errorf("Expected hit rate ~%.1f%%, got %.1f%%", expectedHitRate, hitRate)
	}

	t.Logf("✓ Statistics: hits=%d, misses=%d, size=%d, hit_rate=%.1f%%", hits, misses, size, hitRate)
}
