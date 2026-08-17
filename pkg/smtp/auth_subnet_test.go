package smtp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/logging"
)

// subnetTestConfig returns a config where tier 3 triggers well before tiers
// 1-2 could interfere: per-IP thresholds are high, subnet thresholds low.
func subnetTestConfig() config.ServerAuthRateLimitConfig {
	return config.ServerAuthRateLimitConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 100,
		MaxAttemptsPerIP:         100,
		SubnetMaxDistinctIPs:     4,
		SubnetMinFailures:        6,
		SubnetWindowDuration:     "30m",
		SubnetBlockDuration:      "30m",
		SubnetIPv4Prefix:         24,
		SubnetIPv6Prefix:         48,
		CacheCleanupInterval:     "1h",
	}
}

func newSubnetTestLimiter(t *testing.T, cfg config.ServerAuthRateLimitConfig) *AuthRateLimiter {
	t.Helper()
	limiter, err := NewAuthRateLimiter(cfg, logging.NewTestLogger(), nil)
	if err != nil {
		t.Fatalf("Failed to create limiter: %v", err)
	}
	t.Cleanup(limiter.Shutdown)
	return limiter
}

// TestSubnetBlockOnRotation replays the observed attack: sibling IPs from one
// /24, each failing a couple of times and moving on, so no per-IP counter
// ever accumulates. The subnet must block; an unrelated subnet must not.
func TestSubnetBlockOnRotation(t *testing.T) {
	limiter := newSubnetTestLimiter(t, subnetTestConfig())
	ctx := context.Background()

	// 4 distinct IPs x 2 failures = distinct >= 4, total >= 6
	for i := 1; i <= 4; i++ {
		ip := fmt.Sprintf("213.176.26.%d", 100+i)
		limiter.RecordAuthAttempt(ctx, ip, fmt.Sprintf("user%d", i), false)
		limiter.RecordAuthAttempt(ctx, ip, fmt.Sprintf("user%d", i), false)
	}

	// A fresh sibling never seen before must now be refused
	if err := limiter.CanAttemptAuth(ctx, "213.176.26.250", "victim"); err == nil {
		t.Fatal("expected fresh sibling IP in attacked /24 to be blocked")
	}
	// One of the attacking IPs is refused too
	if err := limiter.CanAttemptAuth(ctx, "213.176.26.101", "victim"); err == nil {
		t.Fatal("expected attacking IP to be blocked")
	}
	// A different /24 is untouched
	if err := limiter.CanAttemptAuth(ctx, "213.176.27.10", "victim"); err != nil {
		t.Fatalf("expected neighboring /24 to be unaffected, got %v", err)
	}
}

// TestSubnetNotTriggeredByFewIPs: failure volume from a small set of
// addresses (the shared-NAT shape) must never block the subnet, however many
// failures accumulate — breadth is the trigger, not volume.
func TestSubnetNotTriggeredByFewIPs(t *testing.T) {
	limiter := newSubnetTestLimiter(t, subnetTestConfig())
	ctx := context.Background()

	for i := 0; i < 30; i++ {
		limiter.RecordAuthAttempt(ctx, "198.51.100.7", "alice", false)
		limiter.RecordAuthAttempt(ctx, "198.51.100.8", "bob", false)
		limiter.RecordAuthAttempt(ctx, "198.51.100.9", "carol", false)
	}

	if _, blocked := limiter.subnetBlocked("198.51.100.50", time.Now()); blocked {
		t.Fatal("3 distinct IPs must not trigger a subnet block regardless of volume")
	}
}

// TestSubnetSuccessExemption: an address that logged in successfully rides
// out a subnet block; strangers do not.
func TestSubnetSuccessExemption(t *testing.T) {
	limiter := newSubnetTestLimiter(t, subnetTestConfig())
	ctx := context.Background()

	// A legitimate user on the subnet logs in first
	limiter.RecordAuthAttempt(ctx, "203.0.113.20", "goodclient", true)

	// Then the rotation attack blocks the /24
	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("203.0.113.%d", 100+i)
		limiter.RecordAuthAttempt(ctx, ip, "admin", false)
		limiter.RecordAuthAttempt(ctx, ip, "admin", false)
	}

	if _, blocked := limiter.subnetBlocked("203.0.113.200", time.Now()); !blocked {
		t.Fatal("expected subnet to be blocked")
	}
	if err := limiter.CanAttemptAuth(ctx, "203.0.113.20", "goodclient"); err != nil {
		t.Fatalf("recently-successful IP must bypass the subnet block, got %v", err)
	}
	if err := limiter.CanAttemptAuth(ctx, "203.0.113.201", "anyone"); err == nil {
		t.Fatal("expected stranger IP in blocked subnet to be refused")
	}
}

// TestSubnetSuccessRemovesMember: a success removes that address from the
// distinct-failure set (the NAT user who mistyped then got in), and the set
// must therefore no longer satisfy the distinct threshold.
func TestSubnetSuccessRemovesMember(t *testing.T) {
	limiter := newSubnetTestLimiter(t, subnetTestConfig())
	ctx := context.Background()

	// 3 failing IPs, one failure each (total stays under SubnetMinFailures so
	// the 4th distinct member cannot instantly trigger the block)...
	for i := 1; i <= 3; i++ {
		limiter.RecordAuthAttempt(ctx, fmt.Sprintf("192.0.2.%d", i), "user", false)
	}
	// ...plus a 4th that fails then succeeds
	limiter.RecordAuthAttempt(ctx, "192.0.2.44", "typo", false)
	limiter.RecordAuthAttempt(ctx, "192.0.2.44", "typo", true)

	limiter.subnetMu.RLock()
	info := limiter.subnets["192.0.2.0/24"]
	_, memberSurvives := info.Members["192.0.2.44"]
	distinct := len(info.Members)
	limiter.subnetMu.RUnlock()
	if memberSurvives {
		t.Fatal("success must remove the address from the subnet failure set")
	}
	if distinct != 3 {
		t.Fatalf("expected 3 remaining members, got %d", distinct)
	}

	// More volume from already-counted IPs: total climbs past the failure
	// threshold, but only 3 distinct members remain — no block
	limiter.RecordAuthAttempt(ctx, "192.0.2.1", "user", false)
	limiter.RecordAuthAttempt(ctx, "192.0.2.2", "user", false)
	limiter.RecordAuthAttempt(ctx, "192.0.2.3", "user", false)

	if _, blocked := limiter.subnetBlocked("192.0.2.99", time.Now()); blocked {
		t.Fatal("member cleared by success must not keep counting toward distinct threshold")
	}
}

// TestSubnetBlockNotLiftedBySuccess: one cracked credential must not lift a
// standing subnet block for everyone else.
func TestSubnetBlockNotLiftedBySuccess(t *testing.T) {
	limiter := newSubnetTestLimiter(t, subnetTestConfig())
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		limiter.RecordAuthAttempt(ctx, ip, "admin", false)
		limiter.RecordAuthAttempt(ctx, ip, "admin", false)
	}
	if _, blocked := limiter.subnetBlocked("203.0.113.99", time.Now()); !blocked {
		t.Fatal("expected subnet block")
	}

	// Attacker cracks one credential from a fresh sibling... except the block
	// refuses the attempt pre-auth; simulate the edge where it lands anyway
	// (e.g. via a good-IP that then authenticates).
	limiter.RecordAuthAttempt(ctx, "203.0.113.7", "cracked", true)

	if _, blocked := limiter.subnetBlocked("203.0.113.99", time.Now()); !blocked {
		t.Fatal("a single success must not lift the subnet block for strangers")
	}
	// But the succeeding IP itself is now exempt
	if err := limiter.CanAttemptAuth(ctx, "203.0.113.7", "cracked"); err != nil {
		t.Fatalf("succeeding IP should be exempt, got %v", err)
	}
}

// TestSubnetPrivateAndExemptNeverBlocked: private ranges and operator-exempt
// CIDRs never accumulate subnet state, however broad the rotation.
func TestSubnetPrivateAndExemptNeverBlocked(t *testing.T) {
	cfg := subnetTestConfig()
	cfg.SubnetExempt = []string{"203.0.113.0/24"}
	limiter := newSubnetTestLimiter(t, cfg)
	ctx := context.Background()

	for i := 1; i <= 20; i++ {
		limiter.RecordAuthAttempt(ctx, fmt.Sprintf("10.0.0.%d", i), "u", false)
		limiter.RecordAuthAttempt(ctx, fmt.Sprintf("203.0.113.%d", i), "u", false)
	}

	if _, blocked := limiter.subnetBlocked("10.0.0.99", time.Now()); blocked {
		t.Fatal("private range must never be subnet-blocked")
	}
	if _, blocked := limiter.subnetBlocked("203.0.113.99", time.Now()); blocked {
		t.Fatal("operator-exempt CIDR must never be subnet-blocked")
	}
}

// TestIPv6MemberBucketing: addresses inside ONE /64 are one identity — for
// tier 2 they share a failure budget, and for tier 3 they count as a single
// distinct member, so rotating within a /64 gains nothing.
func TestIPv6MemberBucketing(t *testing.T) {
	cfg := subnetTestConfig()
	cfg.MaxAttemptsPerIP = 6
	cfg.IPBlockDuration = "30m"
	cfg.IPWindowDuration = "30m"
	limiter := newSubnetTestLimiter(t, cfg)
	ctx := context.Background()

	// 6 failures spread over 6 different addresses in the SAME /64
	for i := 0; i < 6; i++ {
		ip := fmt.Sprintf("2001:db8:1:2::%x", i+1)
		limiter.RecordAuthAttempt(ctx, ip, "user", false)
	}

	// A 7th address in that /64 must be tier-2 blocked: the bucket accumulated
	if err := limiter.CanAttemptAuth(ctx, "2001:db8:1:2::ffff", "user"); err == nil {
		t.Fatal("rotating addresses within one /64 must share one failure budget")
	}

	// And the whole spree registered exactly ONE subnet member
	limiter.subnetMu.RLock()
	info := limiter.subnets["2001:db8:1::/48"]
	limiter.subnetMu.RUnlock()
	if info == nil {
		t.Fatal("expected subnet tracking for the /48")
	}
	if len(info.Members) != 1 {
		t.Fatalf("expected 1 distinct member for one /64, got %d", len(info.Members))
	}
}

// TestIPv6SubnetRotation: rotating across DIFFERENT /64s inside a /48
// triggers the subnet block for the /48.
func TestIPv6SubnetRotation(t *testing.T) {
	limiter := newSubnetTestLimiter(t, subnetTestConfig())
	ctx := context.Background()

	for i := 1; i <= 4; i++ {
		ip := fmt.Sprintf("2001:db8:2:%x::1", i)
		limiter.RecordAuthAttempt(ctx, ip, "user", false)
		limiter.RecordAuthAttempt(ctx, ip, "user", false)
	}

	if err := limiter.CanAttemptAuth(ctx, "2001:db8:2:ffff::1", "user"); err == nil {
		t.Fatal("expected /48 to be blocked after rotation across /64s")
	}
	// Sibling /48 unaffected
	if err := limiter.CanAttemptAuth(ctx, "2001:db8:3:1::1", "user"); err != nil {
		t.Fatalf("expected sibling /48 to be unaffected, got %v", err)
	}
}

// TestSubnetWindowExpiry: members age out of the window, and a stale set no
// longer satisfies the distinct threshold.
func TestSubnetWindowExpiry(t *testing.T) {
	cfg := subnetTestConfig()
	cfg.SubnetWindowDuration = "50ms"
	cfg.SubnetBlockDuration = "50ms"
	limiter := newSubnetTestLimiter(t, cfg)
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		limiter.RecordAuthAttempt(ctx, ip, "u", false)
		limiter.RecordAuthAttempt(ctx, ip, "u", false)
	}
	if _, blocked := limiter.subnetBlocked("203.0.113.99", time.Now()); !blocked {
		t.Fatal("expected subnet block")
	}

	time.Sleep(80 * time.Millisecond)

	// Block expired, and one fresh failure must not re-block (old members
	// fell out of the window)
	limiter.RecordAuthAttempt(ctx, "203.0.113.201", "u", false)
	if _, blocked := limiter.subnetBlocked("203.0.113.99", time.Now()); blocked {
		t.Fatal("expired members must not keep satisfying the distinct threshold")
	}
}

// TestSubnetDisabled: negative SubnetMaxDistinctIPs turns the tier off.
func TestSubnetDisabled(t *testing.T) {
	cfg := subnetTestConfig()
	cfg.SubnetMaxDistinctIPs = -1
	limiter := newSubnetTestLimiter(t, cfg)
	ctx := context.Background()

	for i := 1; i <= 20; i++ {
		limiter.RecordAuthAttempt(ctx, fmt.Sprintf("203.0.113.%d", i), "u", false)
	}
	if err := limiter.CanAttemptAuth(ctx, "203.0.113.250", "u"); err != nil {
		t.Fatalf("disabled tier must never block, got %v", err)
	}
	limiter.subnetMu.RLock()
	tracked := len(limiter.subnets)
	limiter.subnetMu.RUnlock()
	if tracked != 0 {
		t.Fatalf("disabled tier must not accumulate state, got %d subnets", tracked)
	}
}

// TestSubnetUnblockViaCIDR: RemoveIP with CIDR notation lifts the subnet
// block and its state.
func TestSubnetUnblockViaCIDR(t *testing.T) {
	limiter := newSubnetTestLimiter(t, subnetTestConfig())
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		limiter.RecordAuthAttempt(ctx, ip, "u", false)
		limiter.RecordAuthAttempt(ctx, ip, "u", false)
	}
	if _, blocked := limiter.subnetBlocked("203.0.113.99", time.Now()); !blocked {
		t.Fatal("expected subnet block")
	}

	if !limiter.RemoveIP("203.0.113.0/24") {
		t.Fatal("expected RemoveIP with CIDR to report removal")
	}
	if err := limiter.CanAttemptAuth(ctx, "203.0.113.99", "u"); err != nil {
		t.Fatalf("expected subnet to be clear after CIDR unblock, got %v", err)
	}
}

// TestSubnetUnblockNonCanonicalCIDR: an operator entering an address-bearing
// CIDR ("203.0.113.5/24") still lifts the canonical subnet's block.
func TestSubnetUnblockNonCanonicalCIDR(t *testing.T) {
	limiter := newSubnetTestLimiter(t, subnetTestConfig())
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		limiter.RecordAuthAttempt(ctx, ip, "u", false)
		limiter.RecordAuthAttempt(ctx, ip, "u", false)
	}
	if !limiter.RemoveIP("203.0.113.5/24") {
		t.Fatal("expected non-canonical CIDR to unblock the masked subnet")
	}
	if err := limiter.CanAttemptAuth(ctx, "203.0.113.99", "u"); err != nil {
		t.Fatalf("expected subnet clear after unblock, got %v", err)
	}
}

// TestApplyBlockIPFeedsSubnet: peers' BLOCK_IP events count as failing
// members too, so a deployment syncing blocks but not failure counts still
// converges on the subnet verdict.
func TestApplyBlockIPFeedsSubnet(t *testing.T) {
	limiter := newSubnetTestLimiter(t, subnetTestConfig())
	now := time.Now()

	for i := 1; i <= 4; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		limiter.ApplyBlockIP(ip, now.Add(10*time.Minute), 2, now)
	}

	if _, blocked := limiter.subnetBlocked("203.0.113.99", time.Now()); !blocked {
		t.Fatal("cluster IP blocks must feed the subnet tracker")
	}
}

// TestApplyFailureCountFeedsSubnet: FAILURE_COUNT gossip from peers carries
// the failing IP, so a rotation spread across cluster nodes converges on a
// local subnet verdict — and re-reported IPs stay ONE member (idempotent).
func TestApplyFailureCountFeedsSubnet(t *testing.T) {
	limiter := newSubnetTestLimiter(t, subnetTestConfig())
	now := time.Now()

	for i := 1; i <= 4; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		// Same IP reported twice (e.g. rebroadcast): must not double-count
		limiter.ApplyFailureCount(ip, 2, 0, now)
		limiter.ApplyFailureCount(ip, 2, 0, now)
	}

	if _, blocked := limiter.subnetBlocked("203.0.113.99", time.Now()); !blocked {
		t.Fatal("cluster-fed rotation must trigger the local subnet block")
	}

	limiter.subnetMu.RLock()
	info := limiter.subnets["203.0.113.0/24"]
	var total int
	for _, m := range info.Members {
		total += m.FailureCount
	}
	distinct := len(info.Members)
	limiter.subnetMu.RUnlock()
	if distinct != 4 {
		t.Fatalf("expected 4 distinct members, got %d", distinct)
	}
	if total != 8 {
		t.Fatalf("expected max-merged total of 8 (4 IPs x count 2), got %d", total)
	}
}

// TestApplyBlockSubnetFromCluster: a peer's subnet block is enforced locally.
func TestApplyBlockSubnetFromCluster(t *testing.T) {
	limiter := newSubnetTestLimiter(t, subnetTestConfig())
	ctx := context.Background()

	limiter.ApplyBlockSubnet("203.0.113.0/24", time.Now().Add(10*time.Minute), 20, time.Now())

	if err := limiter.CanAttemptAuth(ctx, "203.0.113.5", "u"); err == nil {
		t.Fatal("expected cluster-applied subnet block to be enforced")
	}
}

// TestValidGossipSubnet bounds the blast radius a peer can gossip.
func TestValidGossipSubnet(t *testing.T) {
	cases := []struct {
		subnet string
		want   bool
	}{
		{"203.0.113.0/24", true},
		{"203.0.0.0/16", true},
		{"203.0.112.0/23", true},
		{"0.0.0.0/0", false},      // the internet
		{"203.0.0.0/8", false},    // too broad
		{"203.0.113.5/32", false}, // single host: per-IP events are the vocabulary
		{"203.0.113.1/24", false}, // not masked/canonical
		{"2001:db8:1::/48", true},
		{"2001:db8::/32", true},
		{"2001::/16", false},        // too broad
		{"2001:db8:1:2::/64", true}, // exactly one member identity is allowed
		{"2001:db8:1:2::/80", false},
		{"garbage", false},
		{"", false},
	}
	for _, c := range cases {
		if got := validGossipSubnet(c.subnet); got != c.want {
			t.Errorf("validGossipSubnet(%q) = %v, want %v", c.subnet, got, c.want)
		}
	}
}

// TestBucketIP pins the canonical identity mapping.
func TestBucketIP(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"213.176.26.109", "213.176.26.109"},
		{"::ffff:213.176.26.109", "213.176.26.109"}, // 4-in-6 collapses
		{"2001:db8:1:2:abcd::1", "2001:db8:1:2::"},  // /64 zero address
		{"2001:db8:1:2::", "2001:db8:1:2::"},        // already canonical
		{"not-an-ip", "not-an-ip"},                  // unparseable passes through
	}
	for _, c := range cases {
		if got := bucketIP(c.in); got != c.want {
			t.Errorf("bucketIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSubnetEvictionBound: the subnets map respects MaxSubnetEntries, and
// eviction prefers unblocked entries.
func TestSubnetEvictionBound(t *testing.T) {
	cfg := subnetTestConfig()
	cfg.MaxSubnetEntries = 5
	limiter := newSubnetTestLimiter(t, cfg)
	ctx := context.Background()

	// Block one subnet first
	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		limiter.RecordAuthAttempt(ctx, ip, "u", false)
		limiter.RecordAuthAttempt(ctx, ip, "u", false)
	}
	if _, blocked := limiter.subnetBlocked("203.0.113.99", time.Now()); !blocked {
		t.Fatal("expected subnet block")
	}

	// Flood tracking with other subnets to force eviction
	for i := 0; i < 20; i++ {
		limiter.RecordAuthAttempt(ctx, fmt.Sprintf("198.51.%d.1", i), "u", false)
	}

	limiter.subnetMu.RLock()
	tracked := len(limiter.subnets)
	_, blockedSurvives := limiter.subnets["203.0.113.0/24"]
	limiter.subnetMu.RUnlock()

	if tracked > cfg.MaxSubnetEntries {
		t.Fatalf("subnet map exceeded bound: %d > %d", tracked, cfg.MaxSubnetEntries)
	}
	if !blockedSurvives {
		t.Fatal("eviction must prefer unblocked entries over a live block")
	}
}
