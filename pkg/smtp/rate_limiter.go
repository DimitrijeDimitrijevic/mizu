package smtp

import (
	"io"

	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"log/slog"
	"migadu/mizu/pkg/concurrency"
	"migadu/mizu/pkg/config"
)

// RateLimiterCluster interface allows for testing and abstraction
type RateLimiterCluster interface {
	BroadcastRateLimit(data []byte) error
	RegisterRateLimitHandler(handler func(data []byte))
	// LocalNodeName returns this node's stable name, used to attribute gossiped
	// counts to their source peer so contributions can be summed (not overwritten).
	LocalNodeName() string
}

// maxGossipCount bounds a single peer's reported count for a key. Gossip is
// untrusted; without a cap a malicious/buggy peer could report an enormous
// count to deny a victim key, or overflow the running sum. Any legitimate count
// far exceeds every configured dimension limit well below this ceiling.
const maxGossipCount = 1_000_000

// RateLimiter implements a multi-dimensional sliding window rate limiter with memberlist gossip sync.
// It tracks connection attempts across multiple configurable dimensions (e.g., IP, FROM, TO, combinations).
type RateLimiter struct {
	mu             sync.RWMutex
	enabled        bool
	dimensions     []dimensionTracker           // Configured rate limit dimensions
	windows        map[string]*connectionWindow // composite key -> connection window with local/peer counts
	gossipEnabled  bool
	gossipInterval time.Duration
	// whitelist holds the current exemption set (IPs, domains, senders). It is
	// swapped atomically by the reload loop so CheckRateLimit reads it lock-free.
	whitelist               atomic.Pointer[whitelistSnapshot]
	whitelistSource         *whitelistSource
	whitelistReloadInterval time.Duration
	whitelistFileFP         map[string]string // path -> last-seen fingerprint (reload loop only)
	logger                  *slog.Logger
	cluster                 RateLimiterCluster // Memberlist cluster for gossip
	nodeID                  string             // This node's name (attached to outgoing gossip)
	ctx                     context.Context
	cancel                  context.CancelFunc
}

// dimensionTracker tracks a single rate limit dimension
type dimensionTracker struct {
	name   string        // Human-readable name (e.g., "per_ip", "per_sender")
	keys   []string      // Dimension keys to combine (e.g., ["IP"], ["FROM"], ["IP", "FROM"])
	limit  int           // Max connections per window
	window time.Duration // Time window for rate limiting
}

// connectionWindow tracks connection attempts for a single composite key using a sliding window
// Uses counter-based approach to avoid timestamp accumulation bugs from gossip
type connectionWindow struct {
	localCount  int                         // Connections from this node
	peerCount   int                         // Cached sum of peerCounts (cluster-wide estimate)
	peerCounts  map[string]peerContribution // nodeID -> that peer's last reported count
	windowStart time.Time                   // Start of current window
	lastUpdate  time.Time                   // Last time this window was updated
	lastCleanup time.Time                   // Last time old windows were cleaned up
}

// peerContribution is a single peer's reported count for a window, retained so
// that per-peer contributions can be summed and aged out independently.
type peerContribution struct {
	count      int
	reportedAt time.Time
}

// RateLimitData represents rate limit data that can be gossiped across the cluster
type RateLimitData struct {
	NodeID       string    `json:"node_id"`       // Source node name (for per-peer attribution)
	CompositeKey string    `json:"composite_key"` // e.g., "per_ip|IP:1.2.3.4"
	Count        int       `json:"count"`         // Connection count in current window
	WindowStart  time.Time `json:"window_start"`  // Start of this node's window
	ReportedAt   time.Time `json:"reported_at"`   // When this data was reported
}

// SessionContext holds all the information needed for rate limiting checks
type SessionContext struct {
	RemoteAddr        string   // Remote address (IP:port)
	From              string   // MAIL FROM address
	To                []string // RCPT TO addresses
	AuthenticatedUser string   // Authenticated username (empty if not authenticated)
}

// NewRateLimiter creates a new multi-dimensional rate limiter with memberlist gossip
func NewRateLimiter(rlConfig config.RateLimitConfig, cluster RateLimiterCluster, logger *slog.Logger) *RateLimiter {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Convert config dimensions to internal trackers
	dimensions := make([]dimensionTracker, 0, len(rlConfig.Dimensions))
	for _, d := range rlConfig.Dimensions {
		if d.Limit > 0 && len(d.Keys) > 0 {
			dimensions = append(dimensions, dimensionTracker{
				name:   d.Name,
				keys:   d.Keys,
				limit:  d.Limit,
				window: time.Duration(d.WindowSeconds) * time.Second,
			})
		}
	}

	reloadInterval := time.Duration(rlConfig.WhitelistReloadIntervalSeconds) * time.Second
	if reloadInterval <= 0 {
		reloadInterval = 10 * time.Second
	}

	rl := &RateLimiter{
		enabled:                 rlConfig.Enabled,
		dimensions:              dimensions,
		windows:                 make(map[string]*connectionWindow),
		gossipEnabled:           rlConfig.GossipEnabled,
		gossipInterval:          time.Duration(rlConfig.GossipIntervalSeconds) * time.Second,
		whitelistSource:         newWhitelistSource(rlConfig, logger),
		whitelistReloadInterval: reloadInterval,
		whitelistFileFP:         make(map[string]string),
		logger:                  logger,
		cluster:                 cluster,
		ctx:                     ctx,
		cancel:                  cancel,
	}

	// Build the initial whitelist snapshot and prime file fingerprints so the
	// reload loop only rebuilds on an actual change.
	rl.whitelist.Store(rl.whitelistSource.build())
	for _, path := range rl.whitelistSource.filePaths() {
		rl.whitelistFileFP[path] = fileFingerprint(path)
	}

	// Register handler for rate limit gossip from peers
	if rlConfig.GossipEnabled && cluster != nil {
		rl.nodeID = cluster.LocalNodeName()
		cluster.RegisterRateLimitHandler(rl.handleGossipMessage)
		concurrency.SafeGo(logger, "rate-limiter-gossip", rl.gossipLoop)
	}

	// Start cleanup loop
	concurrency.SafeGo(logger, "rate-limiter-cleanup", rl.cleanupLoop)

	// Watch whitelist files for changes and hot-reload them. Only started when
	// at least one file is configured.
	if len(rl.whitelistSource.filePaths()) > 0 {
		concurrency.SafeGo(logger, "rate-limiter-whitelist-reload", rl.whitelistReloadLoop)
	}

	return rl
}

// whitelistReloadLoop periodically checks the configured whitelist files and
// rebuilds the whitelist snapshot when any of them changes on disk.
func (rl *RateLimiter) whitelistReloadLoop() {
	ticker := time.NewTicker(rl.whitelistReloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			if rl.whitelistFilesChanged() {
				rl.whitelist.Store(rl.whitelistSource.build())
				rl.logger.Info("reloaded rate-limit whitelist files")
			}
		}
	}
}

// whitelistFilesChanged reports whether any watched file's fingerprint changed
// since the last check, updating the stored fingerprints. Only the reload loop
// goroutine touches whitelistFileFP, so no locking is needed.
func (rl *RateLimiter) whitelistFilesChanged() bool {
	changed := false
	for _, path := range rl.whitelistSource.filePaths() {
		if fp := fileFingerprint(path); rl.whitelistFileFP[path] != fp {
			rl.whitelistFileFP[path] = fp
			changed = true
		}
	}
	return changed
}

// CheckRateLimit checks if a session has exceeded any configured rate limits
// Returns nil if allowed, error with dimension name if rate limit exceeded
func (rl *RateLimiter) CheckRateLimit(sessionCtx SessionContext) error {
	if !rl.enabled || len(rl.dimensions) == 0 {
		return nil // Rate limiting disabled
	}

	// Skip rate limiting entirely for whitelisted connections (by IP, or by
	// sender email/domain). A match exempts all dimensions.
	snapshot := rl.whitelist.Load()
	if snapshot.matchesIP(extractIP(sessionCtx.RemoteAddr)) {
		return nil // Whitelisted IP
	}
	if snapshot.matchesSender(sessionCtx.From) {
		return nil // Whitelisted sender
	}

	now := time.Now()

	// Check each dimension independently - any violation rejects the connection
	for _, dim := range rl.dimensions {
		compositeKey := rl.buildCompositeKey(dim.keys, sessionCtx)
		if compositeKey == "" {
			// Skip this dimension if we can't build a key (e.g., FROM dimension but no MAIL FROM yet)
			continue
		}
		// Namespace the window by dimension name so two dimensions that share the
		// same keys (e.g. per-IP-per-minute and per-IP-per-hour) get independent
		// windows instead of colliding and corrupting each other's counts.
		windowKey := dim.name + "|" + compositeKey

		rl.mu.Lock()

		// Get or create window for this composite key
		window, exists := rl.windows[windowKey]
		if !exists {
			window = &connectionWindow{
				localCount:  0,
				peerCount:   0,
				windowStart: now,
				lastUpdate:  now,
				lastCleanup: now,
			}
			rl.windows[windowKey] = window
		}

		// Reset window if it has expired
		if now.Sub(window.windowStart) > dim.window {
			window.localCount = 0
			window.peerCount = 0
			window.peerCounts = nil
			window.windowStart = now
			window.lastUpdate = now
		}

		// Check if adding this connection would exceed the limit (local + peer counts)
		totalCount := window.localCount + window.peerCount
		if totalCount >= dim.limit {
			rl.mu.Unlock()
			rl.logger.Warn("Rate limit exceeded",
				"dimension", dim.name,
				"composite_key", compositeKey,
				"local_count", window.localCount,
				"peer_count", window.peerCount,
				"total", totalCount,
				"limit", dim.limit,
				"window", dim.window)
			return fmt.Errorf("rate limit exceeded for %s: %d/%d connections in %v", dim.name, totalCount, dim.limit, dim.window)
		}

		// Increment local count for this connection
		window.localCount++
		window.lastUpdate = now
		rl.mu.Unlock()
	}

	return nil
}

// buildCompositeKey builds a composite key from the specified dimension keys and session context
// Returns empty string if any required key is not available
func (rl *RateLimiter) buildCompositeKey(keys []string, sessionCtx SessionContext) string {
	parts := make([]string, 0, len(keys))

	for _, key := range keys {
		switch strings.ToUpper(key) {
		case "IP":
			ip := extractIP(sessionCtx.RemoteAddr)
			if ip == "" {
				return "" // Can't build key without IP
			}
			parts = append(parts, fmt.Sprintf("IP:%s", ip))

		case "FROM":
			if sessionCtx.From == "" {
				return "" // Can't build key without FROM
			}
			parts = append(parts, fmt.Sprintf("FROM:%s", strings.ToLower(sessionCtx.From)))

		case "FROM_DOMAIN":
			domain := extractDomain(sessionCtx.From)
			if domain == "" {
				return "" // Can't build key without FROM domain
			}
			parts = append(parts, fmt.Sprintf("FROM_DOMAIN:%s", strings.ToLower(domain)))

		case "TO":
			if len(sessionCtx.To) == 0 {
				return "" // Can't build key without TO
			}
			// For multiple recipients, use the first one (or could iterate per-recipient)
			parts = append(parts, fmt.Sprintf("TO:%s", strings.ToLower(sessionCtx.To[0])))

		case "TO_DOMAIN":
			if len(sessionCtx.To) == 0 {
				return "" // Can't build key without TO
			}
			domain := extractDomain(sessionCtx.To[0])
			if domain == "" {
				return "" // Can't build key without TO domain
			}
			parts = append(parts, fmt.Sprintf("TO_DOMAIN:%s", strings.ToLower(domain)))

		case "AUTHENTICATED_USER":
			if sessionCtx.AuthenticatedUser == "" {
				return "" // Can't build key without authenticated user
			}
			parts = append(parts, fmt.Sprintf("USER:%s", strings.ToLower(sessionCtx.AuthenticatedUser)))

		default:
			rl.logger.Warn("Unknown rate limit dimension key", "key", key)
			return "" // Unknown key type
		}
	}

	if len(parts) == 0 {
		return ""
	}

	// Sort parts to ensure consistent key regardless of order in config
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// extractIP extracts the IP address from a remote address string (removes port)
func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr // Already just an IP
	}
	return host
}

// extractDomain extracts the domain part from an email address
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// gossipLoop periodically sends rate limit data to cluster peers
func (rl *RateLimiter) gossipLoop() {
	ticker := time.NewTicker(rl.gossipInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			rl.sendGossip()
		}
	}
}

// sendGossip broadcasts current rate limit state via memberlist
func (rl *RateLimiter) sendGossip() {
	rl.mu.RLock()

	// Collect data for all composite keys (only send non-zero local counts)
	now := time.Now()
	data := make([]RateLimitData, 0, len(rl.windows))

	for compositeKey, window := range rl.windows {
		if window.localCount > 0 {
			data = append(data, RateLimitData{
				NodeID:       rl.nodeID,
				CompositeKey: compositeKey,
				Count:        window.localCount,
				WindowStart:  window.windowStart,
				ReportedAt:   now,
			})
		}
	}

	rl.mu.RUnlock()

	if len(data) == 0 {
		return // Nothing to gossip
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		rl.logger.Error("Failed to marshal rate limit data", "error", err)
		return
	}

	if err := rl.cluster.BroadcastRateLimit(jsonData); err != nil {
		rl.logger.Debug("Failed to broadcast rate limit data", "error", err)
	}
}

// handleGossipMessage processes rate limit gossip messages from memberlist
func (rl *RateLimiter) handleGossipMessage(data []byte) {
	var rateLimitData []RateLimitData
	if err := json.Unmarshal(data, &rateLimitData); err != nil {
		rl.logger.Warn("Failed to unmarshal rate limit gossip data", "error", err)
		return
	}

	rl.MergeGossipData(rateLimitData)
}

// MergeGossipData merges received gossip data into local state.
//
// Each gossip batch carries one peer's own counts. Contributions are tracked
// per source node (window.peerCounts[nodeID]) and summed, so a batch from peer B
// does not overwrite peer A's contribution — the previous implementation zeroed
// all peer counts and rebuilt from a single batch, collapsing the cluster-wide
// estimate to whichever peer gossiped last. A key that is absent from a peer's
// batch means that peer's count for it is now zero, so the peer's prior entries
// are cleared before the batch is applied.
//
// Gossip is untrusted, so counts are validated: negative counts (which could
// disable limiting) and absurdly large counts (which could deny a victim key or
// overflow the sum) are rejected, and unattributed batches are ignored.
func (rl *RateLimiter) MergeGossipData(data []RateLimitData) {
	if !rl.gossipEnabled {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	maxWindow := rl.getMaxWindow()

	// Identify the peer(s) reporting in this batch so we can replace only their
	// contribution across all windows.
	reportingNodes := make(map[string]bool)
	for _, item := range data {
		if item.NodeID != "" && item.NodeID != rl.nodeID {
			reportingNodes[item.NodeID] = true
		}
	}
	for _, window := range rl.windows {
		for nodeID := range reportingNodes {
			delete(window.peerCounts, nodeID)
		}
	}

	// Apply the reported (and validated) counts, attributed to their source node.
	for _, item := range data {
		if now.Sub(item.ReportedAt) > maxWindow {
			continue // Stale
		}
		if item.NodeID == "" || item.NodeID == rl.nodeID {
			continue // Unattributable, or our own count echoed back
		}
		if item.Count < 0 || item.Count > maxGossipCount {
			rl.logger.Warn("Rejecting out-of-range rate-limit gossip count",
				"composite_key", item.CompositeKey, "count", item.Count, "node", item.NodeID)
			continue
		}

		window, exists := rl.windows[item.CompositeKey]
		if !exists {
			window = &connectionWindow{
				windowStart: item.WindowStart,
				lastUpdate:  now,
				lastCleanup: now,
			}
			rl.windows[item.CompositeKey] = window
		}
		if window.peerCounts == nil {
			window.peerCounts = make(map[string]peerContribution)
		}
		window.peerCounts[item.NodeID] = peerContribution{count: item.Count, reportedAt: item.ReportedAt}
	}

	// Recompute cached peer sums, pruning contributions from peers we haven't
	// heard from within the window.
	for _, window := range rl.windows {
		sum := 0
		for nodeID, pc := range window.peerCounts {
			if now.Sub(pc.reportedAt) > maxWindow {
				delete(window.peerCounts, nodeID)
				continue
			}
			sum += pc.count
		}
		window.peerCount = sum
	}
}

// getMaxWindow returns the maximum window duration across all dimensions
func (rl *RateLimiter) getMaxWindow() time.Duration {
	maxWindow := time.Minute
	for _, dim := range rl.dimensions {
		if dim.window > maxWindow {
			maxWindow = dim.window
		}
	}
	return maxWindow
}

// cleanupLoop periodically removes old entries to prevent memory leaks
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			rl.cleanup()
		}
	}
}

// cleanup removes old windows that are no longer active
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	maxWindow := rl.getMaxWindow()
	staleThreshold := maxWindow * 2 // Keep windows for 2x max window

	removed := 0
	for compositeKey, window := range rl.windows {
		// Remove windows that haven't been updated recently and have no counts
		if window.localCount == 0 && window.peerCount == 0 && now.Sub(window.lastUpdate) > staleThreshold {
			delete(rl.windows, compositeKey)
			removed++
		}
	}

	// Proactive memory management: if still above threshold, remove oldest windows
	const maxWindows = 100000 // Maximum number of windows to keep in memory
	if len(rl.windows) > maxWindows {
		rl.proactiveEvictWindows(maxWindows)
	}

	if removed > 0 {
		rl.logger.Debug("cleaned up stale rate limit windows",
			"removed", removed,
			"remaining", len(rl.windows))
	}
}

// proactiveEvictWindows evicts oldest windows when memory limit is exceeded
// This prevents unbounded memory growth under attack scenarios
func (rl *RateLimiter) proactiveEvictWindows(targetSize int) {
	// Already holding lock from cleanup()

	toEvict := len(rl.windows) - targetSize + (targetSize / 10) // Evict extra 10% for headroom
	if toEvict <= 0 {
		return
	}

	// Sort windows by last update time (oldest first)
	type windowEntry struct {
		key        string
		lastUpdate time.Time
	}

	entries := make([]windowEntry, 0, len(rl.windows))
	for key, window := range rl.windows {
		entries = append(entries, windowEntry{
			key:        key,
			lastUpdate: window.lastUpdate,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastUpdate.Before(entries[j].lastUpdate)
	})

	// Evict oldest entries
	evicted := 0
	for i := 0; i < toEvict && i < len(entries); i++ {
		delete(rl.windows, entries[i].key)
		evicted++
	}

	rl.logger.Warn("proactively evicted rate limit windows to prevent memory exhaustion",
		"evicted", evicted,
		"remaining", len(rl.windows),
		"target", targetSize)
}

// Shutdown stops the rate limiter's background goroutines
func (rl *RateLimiter) Shutdown() {
	if rl.cancel != nil {
		rl.cancel()
	}
}

// GetStats returns current rate limiter statistics for monitoring
func (rl *RateLimiter) GetStats() map[string]any {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	stats := map[string]any{
		"enabled":         rl.enabled,
		"total_windows":   len(rl.windows),
		"gossip_enabled":  rl.gossipEnabled,
		"dimension_count": len(rl.dimensions),
	}

	// Add per-dimension stats
	dimensions := make([]map[string]any, 0, len(rl.dimensions))
	for _, dim := range rl.dimensions {
		dimensions = append(dimensions, map[string]any{
			"name":   dim.name,
			"keys":   dim.keys,
			"limit":  dim.limit,
			"window": dim.window.String(),
		})
	}
	stats["dimensions"] = dimensions

	return stats
}
