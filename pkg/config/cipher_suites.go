package config

import (
	"crypto/tls"
	"fmt"
	"slices"
	"strings"
)

// usableBelowTLS13 reports whether cs can be negotiated under TLS 1.0-1.2.
// crypto/tls lists its TLS 1.3 suites alongside them, but ignores
// Config.CipherSuites for 1.3, so naming one would be accepted and do nothing.
func usableBelowTLS13(cs *tls.CipherSuite) bool {
	return slices.ContainsFunc(cs.SupportedVersions, func(v uint16) bool {
		return v < tls.VersionTLS13
	})
}

// cipherSuitesByName indexes every TLS 1.0-1.2 cipher suite crypto/tls implements
// — secure and insecure alike — by its Go name. The insecure ones are included
// deliberately: they are the whole point of extra_cipher_suites. TLS 1.3 suites
// are excluded, so naming one fails startup instead of silently doing nothing.
var cipherSuitesByName = func() map[string]uint16 {
	all := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	m := make(map[string]uint16, len(all))
	for _, cs := range all {
		if usableBelowTLS13(cs) {
			m[cs.Name] = cs.ID
		}
	}
	return m
}()

// secureCipherSuiteIDs is Go's list of TLS 1.0-1.2 suites without known
// weaknesses, in the order crypto/tls reports them. Order carries no meaning:
// the server re-sorts any configured set by its own preference, which ranks
// every ECDHE suite above every RSA key exchange one.
var secureCipherSuiteIDs = func() []uint16 {
	secure := tls.CipherSuites()
	ids := make([]uint16, 0, len(secure))
	for _, cs := range secure {
		if usableBelowTLS13(cs) {
			ids = append(ids, cs.ID)
		}
	}
	return ids
}()

// knownCipherSuiteNames lists every accepted extra_cipher_suites value, for
// error messages.
func knownCipherSuiteNames() []string {
	names := make([]string, 0, len(cipherSuitesByName))
	for name := range cipherSuitesByName {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// resolveCipherSuites maps extra_cipher_suites names to their IDs, rejecting
// anything crypto/tls does not implement. Duplicates are dropped.
func resolveCipherSuites(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil
	}
	ids := make([]uint16, 0, len(names))
	for _, name := range names {
		id, ok := cipherSuitesByName[strings.ToUpper(strings.TrimSpace(name))]
		if !ok {
			return nil, fmt.Errorf("unknown cipher suite %q (valid values: %s)",
				name, strings.Join(knownCipherSuiteNames(), ", "))
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}
