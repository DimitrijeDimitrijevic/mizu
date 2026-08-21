package smtp

import (
	"fmt"
	"net"
	"os"
	"strings"

	"log/slog"
	"migadu/mizu/pkg/config"
)

// whitelistSnapshot is an immutable set of rate-limit whitelist entries. The
// RateLimiter holds it behind an atomic pointer and swaps it wholesale when a
// whitelist file changes, so CheckRateLimit reads it on the hot path without
// locking. A whitelist match exempts a message from ALL rate limit dimensions.
type whitelistSnapshot struct {
	ipNets  []*net.IPNet    // Whitelisted IPs/CIDRs
	domains map[string]bool // Lowercased sender domains
	senders map[string]bool // Lowercased sender addresses
}

// matchesIP reports whether ip (a bare address, no port) is whitelisted.
func (s *whitelistSnapshot) matchesIP(ip string) bool {
	if s == nil || ip == "" || len(s.ipNets) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range s.ipNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// matchesSender reports whether a MAIL FROM address is whitelisted, by exact
// address or by its domain.
func (s *whitelistSnapshot) matchesSender(from string) bool {
	if s == nil || from == "" {
		return false
	}
	from = strings.ToLower(from)
	if s.senders[from] {
		return true
	}
	domain := extractDomain(from)
	return domain != "" && s.domains[domain]
}

// whitelistSource holds the inline config entries and file paths needed to
// (re)build a whitelistSnapshot. It is immutable after construction; build()
// re-reads the files each call so removing a line from a file removes the entry.
type whitelistSource struct {
	inlineIPs     []string
	inlineDomains []string
	inlineSenders []string
	ipsFile       string
	domainsFile   string
	sendersFile   string
	logger        *slog.Logger
}

func newWhitelistSource(cfg config.RateLimitConfig, logger *slog.Logger) *whitelistSource {
	return &whitelistSource{
		inlineIPs:     cfg.WhitelistedIPs,
		inlineDomains: cfg.WhitelistedDomains,
		inlineSenders: cfg.WhitelistedSenders,
		ipsFile:       cfg.WhitelistedIPsFile,
		domainsFile:   cfg.WhitelistedDomainsFile,
		sendersFile:   cfg.WhitelistedSendersFile,
		logger:        logger,
	}
}

// filePaths returns the configured whitelist file paths (skipping unset ones).
func (src *whitelistSource) filePaths() []string {
	paths := make([]string, 0, 3)
	for _, p := range []string{src.ipsFile, src.domainsFile, src.sendersFile} {
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

// build assembles a fresh snapshot from the inline entries unioned with the
// current file contents. Malformed IP entries from files are skipped and logged
// rather than dropping the whole list.
func (src *whitelistSource) build() *whitelistSnapshot {
	domains := make(map[string]bool)
	for _, d := range src.inlineDomains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			domains[d] = true
		}
	}
	for _, d := range readWhitelistFile(src.domainsFile, src.logger) {
		domains[strings.ToLower(d)] = true
	}

	senders := make(map[string]bool)
	for _, s := range src.inlineSenders {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			senders[s] = true
		}
	}
	for _, s := range readWhitelistFile(src.sendersFile, src.logger) {
		senders[strings.ToLower(s)] = true
	}

	// Inline IPs are validated at startup by config.Validate; file IPs are
	// parsed leniently here so one bad line can't drop the whole list.
	var ipNets []*net.IPNet
	entries := append(append([]string{}, src.inlineIPs...), readWhitelistFile(src.ipsFile, src.logger)...)
	for _, entry := range entries {
		nets, err := config.ParseIPList([]string{entry})
		if err != nil {
			src.logger.Warn("skipping invalid rate-limit whitelist IP", "entry", entry, "error", err)
			continue
		}
		ipNets = append(ipNets, nets...)
	}

	return &whitelistSnapshot{ipNets: ipNets, domains: domains, senders: senders}
}

// readWhitelistFile reads a newline-delimited whitelist file, returning trimmed
// non-empty entries. Blank lines and comments (a '#' and everything after it on
// a line) are ignored. A missing or unreadable file yields no entries and a
// warning; the reload loop picks the file up once it appears.
func readWhitelistFile(path string, logger *slog.Logger) []string {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		logger.Warn("rate-limit whitelist file unreadable, treating as empty", "path", path, "error", err)
		return nil
	}
	var entries []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			entries = append(entries, line)
		}
	}
	return entries
}

// fileFingerprint returns a modtime+size string used to detect whitelist file
// changes. Missing or unreadable files fingerprint as "" so a file appearing or
// disappearing registers as a change.
func fileFingerprint(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d:%d", info.ModTime().UnixNano(), info.Size())
}
