package smtp

import (
	"net/netip"
	"sort"
	"time"
)

// Tier 3: subnet blocking.
//
// Tiers 1-2 key on the single address, which an attacker rotating through
// sibling IPs resets at will — the observed shape is one connection, one
// failure, next address, so a /24 hands out 256 fresh budgets per window.
// This tier keeps a windowed record of WHICH addresses inside a subnet
// failed authentication and blocks the subnet once that set is broad enough.
// Breadth is the discriminator, not volume: a shared NAT produces failures
// from a handful of egress addresses interleaved with successes; the
// rotation attack produces many distinct addresses and no successes.
//
// Safety properties, in order of importance:
//   - The refusal is ErrAuthRateLimited (454, temporary) — a legitimate
//     client caught inside a blocked subnet retries later and self-heals;
//     it is never told its password is wrong.
//   - An address with a recent successful login bypasses subnet blocks
//     entirely (tiers 1-2 still bound it individually), so known-good
//     clients on a mixed subnet never feel the collective punishment.
//   - Loopback, private and operator-exempted ranges are never blocked.

// ipv6MemberBits is the identity granularity for IPv6: one /64 is one
// subscriber under standard allocation, so every per-"IP" counter in this
// limiter keys v6 addresses by their /64. Counting full addresses would hand
// a v6 attacker 2^64 free identities inside one allocation.
const ipv6MemberBits = 64

// maxSubnetMembers bounds one subnet's distinct-member set. IPv4 can never
// reach it (a /24 holds 256 addresses); a v6 /48 holds 65536 /64s, but past
// this cap distinctness is proven many times over — new members are simply
// not recorded, which can only delay a block, never cause one.
const maxSubnetMembers = 1024

// bucketIP canonicalizes an address into the identity every tier keys on:
// IPv4 (and 4-in-6) collapse to the plain dotted form, IPv6 collapses to the
// zero address of its /64 (e.g. "2001:db8:1:2::"). The result is still a
// parseable address, so gossip sanitization and metric labels are unaffected.
// Unparseable input is returned unchanged — a weird key still limits itself.
func bucketIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(ipv6MemberBits)
	if err != nil {
		return addr.String()
	}
	return prefix.Addr().String()
}

// subnetMember is one distinct failing identity inside a subnet (an IPv4
// address or an IPv6 /64), with enough recency to window it out.
type subnetMember struct {
	FailureCount int
	LastFailure  time.Time
}

// SubnetInfo tracks a subnet's windowed failure set and block state.
type SubnetInfo struct {
	Subnet       string
	Members      map[string]*subnetMember
	FirstFailure time.Time
	BlockedUntil time.Time
}

// subnetKeyOf maps a (bucketed) address to its tier-3 subnet, or "" when the
// address must never be subnet-blocked: unparseable, loopback/private/
// link-local, or inside an operator-exempt CIDR. Tiers 1-2 still apply to
// exempted addresses individually.
func (a *AuthRateLimiter) subnetKeyOf(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return ""
	}
	for _, exempt := range a.subnetExempt {
		if exempt.Contains(addr) {
			return ""
		}
	}
	bits := a.config.SubnetIPv4Prefix
	if addr.Is6() {
		bits = a.config.SubnetIPv6Prefix
	}
	if bits <= 0 {
		return ""
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}
	return prefix.String()
}

// noteSubnetFailure records one failing address into its subnet's windowed
// set and blocks the subnet when the set is broad enough. clusterCount == 0
// means a locally-witnessed failure (increment); a positive value is a
// cumulative per-address count from cluster gossip and merges as max, not
// sum — the same attempts may be rebroadcast, and undercounting can only
// delay a block.
func (a *AuthRateLimiter) noteSubnetFailure(ip string, clusterCount int, now time.Time) {
	if a.config.SubnetMaxDistinctIPs <= 0 {
		return
	}
	subnet := a.subnetKeyOf(ip)
	if subnet == "" {
		return
	}

	a.subnetMu.Lock()
	defer a.subnetMu.Unlock()

	info, exists := a.subnets[subnet]
	if !exists {
		if a.config.MaxSubnetEntries > 0 && len(a.subnets) >= a.config.MaxSubnetEntries {
			a.proactiveEvictSubnets()
		}
		info = &SubnetInfo{
			Subnet:       subnet,
			Members:      make(map[string]*subnetMember),
			FirstFailure: now,
		}
		a.subnets[subnet] = info
	}

	// The window lives on each member, not the subnet: pruning stale members
	// keeps the distinct count honest without resetting a live attack.
	pruneSubnetMembers(info, now, a.subnetWindowDuration)
	if len(info.Members) == 0 {
		info.FirstFailure = now
	}

	member, ok := info.Members[ip]
	if !ok {
		if len(info.Members) >= maxSubnetMembers {
			return
		}
		member = &subnetMember{}
		info.Members[ip] = member
	}
	if clusterCount > 0 {
		if clusterCount > member.FailureCount {
			member.FailureCount = clusterCount
		}
	} else {
		member.FailureCount++
	}
	member.LastFailure = now

	distinct := len(info.Members)
	total := 0
	for _, m := range info.Members {
		total += m.FailureCount
	}
	if distinct < a.config.SubnetMaxDistinctIPs || total < a.config.SubnetMinFailures {
		return
	}

	blockedUntil := now.Add(a.subnetBlockDuration)
	if !blockedUntil.After(info.BlockedUntil) {
		return
	}
	newBlock := !now.Before(info.BlockedUntil)
	info.BlockedUntil = blockedUntil
	if !newBlock {
		// Extension of a live block (fed by cluster gossip); no re-announce.
		return
	}

	a.logger.Warn("blocking subnet",
		"subnet", subnet,
		"distinct_ips", distinct,
		"failure_count", total,
		"blocked_until", blockedUntil)

	if a.metrics != nil {
		a.metrics.AuthRateLimitSubnetBlocks.WithLabelValues(subnet).Inc()
	}

	if a.clusterLimiter != nil && a.config.ClusterSyncEnabled && a.config.SyncBlocks {
		a.clusterLimiter.BroadcastBlockSubnet(subnet, blockedUntil, total, info.FirstFailure)
	}
}

// subnetBlocked answers whether tier 3 refuses this (bucketed) address, and
// until when. An address with a recent successful login passes: collective
// punishment must not reach known-good clients on a mixed subnet, and tiers
// 1-2 still bound what that individual address can attempt.
func (a *AuthRateLimiter) subnetBlocked(ip string, now time.Time) (time.Time, bool) {
	if a.config.SubnetMaxDistinctIPs <= 0 {
		return time.Time{}, false
	}
	subnet := a.subnetKeyOf(ip)
	if subnet == "" {
		return time.Time{}, false
	}
	a.subnetMu.RLock()
	info, exists := a.subnets[subnet]
	var blockedUntil time.Time
	if exists {
		blockedUntil = info.BlockedUntil
	}
	a.subnetMu.RUnlock()
	if !now.Before(blockedUntil) {
		return time.Time{}, false
	}
	if a.isRecentlyGood(ip, now) {
		return time.Time{}, false
	}
	return blockedUntil, true
}

// clearSubnetMember removes one address from its subnet's failure set after
// a successful login — a NAT user who mistyped twice then got in stops
// counting toward their neighbors' fate. Deliberately does NOT touch
// BlockedUntil: one cracked credential inside a subnet must not lift the
// block or launder the evidence.
func (a *AuthRateLimiter) clearSubnetMember(ip string) {
	if a.config.SubnetMaxDistinctIPs <= 0 {
		return
	}
	subnet := a.subnetKeyOf(ip)
	if subnet == "" {
		return
	}
	a.subnetMu.Lock()
	if info, ok := a.subnets[subnet]; ok {
		delete(info.Members, ip)
	}
	a.subnetMu.Unlock()
}

// recordGoodIP stamps a successful login for the subnet-block bypass.
func (a *AuthRateLimiter) recordGoodIP(ip string, now time.Time) {
	if a.successExemptDuration <= 0 {
		return
	}
	a.goodMu.Lock()
	defer a.goodMu.Unlock()
	if _, ok := a.goodIPs[ip]; !ok && a.config.MaxIPEntries > 0 && len(a.goodIPs) >= a.config.MaxIPEntries {
		a.proactiveEvictGoodIPs()
	}
	a.goodIPs[ip] = now
}

// isRecentlyGood reports whether this address logged in successfully within
// the exemption window.
func (a *AuthRateLimiter) isRecentlyGood(ip string, now time.Time) bool {
	a.goodMu.RLock()
	defer a.goodMu.RUnlock()
	seen, ok := a.goodIPs[ip]
	return ok && now.Sub(seen) <= a.successExemptDuration
}

// ApplyBlockSubnet applies a subnet block from cluster sync.
func (a *AuthRateLimiter) ApplyBlockSubnet(subnet string, blockedUntil time.Time, failureCount int, firstFailure time.Time) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return
	}
	subnet = prefix.Masked().String()

	a.subnetMu.Lock()
	defer a.subnetMu.Unlock()

	info, exists := a.subnets[subnet]
	if !exists {
		if a.config.MaxSubnetEntries > 0 && len(a.subnets) >= a.config.MaxSubnetEntries {
			a.proactiveEvictSubnets()
		}
		info = &SubnetInfo{
			Subnet:       subnet,
			Members:      make(map[string]*subnetMember),
			FirstFailure: firstFailure,
		}
		a.subnets[subnet] = info
	}
	if blockedUntil.After(info.BlockedUntil) {
		info.BlockedUntil = blockedUntil
		a.logger.Info("applied subnet block from cluster",
			"subnet", subnet,
			"blocked_until", blockedUntil,
			"failure_count", failureCount)
	}
}

// ApplyUnblockSubnet drops a subnet's block and failure set (local only).
// Returns true if anything was tracked.
func (a *AuthRateLimiter) ApplyUnblockSubnet(subnet string) bool {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return false
	}
	subnet = prefix.Masked().String()

	a.subnetMu.Lock()
	defer a.subnetMu.Unlock()

	_, exists := a.subnets[subnet]
	if exists {
		delete(a.subnets, subnet)
		a.logger.Info("subnet unblocked", "subnet", subnet)
	}
	return exists
}

// pruneSubnetMembers drops members whose last failure fell out of the window.
func pruneSubnetMembers(info *SubnetInfo, now time.Time, window time.Duration) {
	for ip, m := range info.Members {
		if now.Sub(m.LastFailure) > window {
			delete(info.Members, ip)
		}
	}
}

// proactiveEvictSubnets evicts oldest subnet entries when at capacity.
// Caller holds subnetMu. Actively-blocked subnets are evicted last — evicting
// one would unblock a live attacker to make room for bookkeeping.
func (a *AuthRateLimiter) proactiveEvictSubnets() {
	toEvict := a.config.MaxSubnetEntries / 5
	if toEvict < 1 {
		toEvict = 1
	}

	now := time.Now()
	type kv struct {
		key     string
		blocked bool
		time    time.Time
	}
	entries := make([]kv, 0, len(a.subnets))
	for k, v := range a.subnets {
		entries = append(entries, kv{k, now.Before(v.BlockedUntil), v.FirstFailure})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].blocked != entries[j].blocked {
			return !entries[i].blocked
		}
		return entries[i].time.Before(entries[j].time)
	})

	evicted := 0
	for i := 0; i < toEvict && i < len(entries); i++ {
		delete(a.subnets, entries[i].key)
		evicted++
	}

	a.logger.Debug("proactively evicted subnet entries",
		"evicted", evicted,
		"remaining", len(a.subnets))

	if a.metrics != nil {
		a.metrics.AuthRateLimitEvictions.WithLabelValues("subnet").Add(float64(evicted))
		a.metrics.AuthRateLimitCacheSize.WithLabelValues("subnet").Set(float64(len(a.subnets)))
	}
}

// proactiveEvictGoodIPs evicts oldest success stamps when at capacity.
// Caller holds goodMu.
func (a *AuthRateLimiter) proactiveEvictGoodIPs() {
	toEvict := a.config.MaxIPEntries / 5
	if toEvict < 1 {
		toEvict = 1
	}

	type kv struct {
		key  string
		time time.Time
	}
	entries := make([]kv, 0, len(a.goodIPs))
	for k, v := range a.goodIPs {
		entries = append(entries, kv{k, v})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].time.Before(entries[j].time)
	})

	evicted := 0
	for i := 0; i < toEvict && i < len(entries); i++ {
		delete(a.goodIPs, entries[i].key)
		evicted++
	}

	a.logger.Debug("proactively evicted good-IP entries",
		"evicted", evicted,
		"remaining", len(a.goodIPs))

	if a.metrics != nil {
		a.metrics.AuthRateLimitEvictions.WithLabelValues("good_ip").Add(float64(evicted))
		a.metrics.AuthRateLimitCacheSize.WithLabelValues("good_ip").Set(float64(len(a.goodIPs)))
	}
}
