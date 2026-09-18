package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestResolveCipherSuites(t *testing.T) {
	t.Run("empty yields no IDs", func(t *testing.T) {
		ids, err := resolveCipherSuites(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ids != nil {
			t.Fatalf("expected nil IDs, got %v", ids)
		}
	})

	t.Run("resolves insecure suites", func(t *testing.T) {
		// The suites Go disables by default are the entire reason this option
		// exists, so they must resolve.
		ids, err := resolveCipherSuites([]string{
			"TLS_RSA_WITH_AES_128_CBC_SHA",
			"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}
		if !slices.Equal(ids, want) {
			t.Fatalf("got %v, want %v", ids, want)
		}
	})

	t.Run("normalizes case and whitespace", func(t *testing.T) {
		ids, err := resolveCipherSuites([]string{"  tls_rsa_with_aes_128_cbc_sha  "})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !slices.Equal(ids, []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}) {
			t.Fatalf("got %v", ids)
		}
	})

	t.Run("drops duplicates", func(t *testing.T) {
		ids, err := resolveCipherSuites([]string{
			"TLS_RSA_WITH_AES_128_CBC_SHA",
			"TLS_RSA_WITH_AES_128_CBC_SHA",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ids) != 1 {
			t.Fatalf("expected 1 ID, got %v", ids)
		}
	})

	t.Run("rejects unknown names", func(t *testing.T) {
		// A typo must fail startup rather than silently leaving the appliance
		// unable to connect.
		_, err := resolveCipherSuites([]string{"TLS_RSA_WITH_AES_128_CBC_SHA1"})
		if err == nil {
			t.Fatal("expected an error for an unknown suite name")
		}
		if !strings.Contains(err.Error(), "TLS_RSA_WITH_AES_128_CBC_SHA") {
			t.Fatalf("error should list valid names, got: %v", err)
		}
	})
}

func TestServerTLSConfigCipherSuites(t *testing.T) {
	t.Run("nil without extras", func(t *testing.T) {
		// nil leaves crypto/tls on its own defaults, which is what every
		// listener that does not opt in must keep.
		var cfg ServerTLSConfig
		if got := cfg.CipherSuites(); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})

	t.Run("extras are added to the secure defaults, not substituted", func(t *testing.T) {
		cfg := ServerTLSConfig{cipherSuiteIDs: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}
		got := cfg.CipherSuites()
		for _, id := range secureCipherSuiteIDs {
			if !slices.Contains(got, id) {
				t.Fatalf("secure suite %s was dropped", tls.CipherSuiteName(id))
			}
		}
		if !slices.Contains(got, tls.TLS_RSA_WITH_AES_128_CBC_SHA) {
			t.Fatal("extra suite missing")
		}
	})
}

// TestValidateResolvesCipherSuites covers the wiring: Validate must leave the
// resolved IDs on the server it was called for, or CipherSuites() returns
// nothing and the listener silently keeps the defaults.
func TestValidateResolvesCipherSuites(t *testing.T) {
	newServer := func(extra []string) ServerConfig {
		return ServerConfig{
			Name:       "relay-25",
			ListenAddr: ":25",
			Type:       "relay",
			TLS: ServerTLSConfig{
				Enabled:           true,
				Mode:              "starttls",
				ExtraCipherSuites: extra,
			},
			Delivery: DeliveryConfig{
				URL:                "https://backend.example.com/deliver",
				AuthToken:          "token",
				MaxRetryAttempts:   3,
				HTTPTimeoutSeconds: 30,
			},
		}
	}

	t.Run("resolved through Config.Validate", func(t *testing.T) {
		// Go through the real defaults: Config.Validate applies them first, and
		// a zero Defaults block trips unrelated required fields.
		cfg := DefaultConfig()
		cfg.Storage.Backend = "filesystem" // avoid the S3 credential requirement
		cfg.Servers = []ServerConfig{newServer([]string{"TLS_RSA_WITH_AES_128_CBC_SHA"})}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		suites := cfg.Servers[0].TLS.CipherSuites()
		if !slices.Contains(suites, tls.TLS_RSA_WITH_AES_128_CBC_SHA) {
			t.Fatalf("extra suite not resolved onto the server: %v", suites)
		}
	})

	t.Run("an unknown name fails startup", func(t *testing.T) {
		s := newServer([]string{"TLS_RSA_WITH_UNOBTAINIUM_128"})
		if err := s.Validate(); err == nil {
			t.Fatal("expected validation to fail")
		} else if !strings.Contains(err.Error(), "extra_cipher_suites") {
			t.Fatalf("error should name the option, got: %v", err)
		}
	})

	t.Run("no extras leaves the defaults", func(t *testing.T) {
		s := newServer(nil)
		if err := s.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := s.TLS.CipherSuites(); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})
}

// rsaTestCert returns a self-signed RSA certificate. RSA specifically: the
// legacy suites this option restores all use RSA key exchange, which cannot be
// negotiated against an ECDSA certificate.
func rsaTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mx.test.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"mx.test.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshake runs one TLS handshake over an in-memory pipe and reports the
// server's error and the suite it negotiated.
func handshake(t *testing.T, serverCfg, clientCfg *tls.Config) (uint16, error) {
	t.Helper()
	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tls.Client(clientConn, clientCfg).Handshake()
	}()

	server := tls.Server(serverConn, serverCfg)
	err := server.Handshake()
	state := server.ConnectionState()

	// Tear down by closing the pipes rather than the tls.Conns. Closing a
	// tls.Conn writes close_notify, which blocks for crypto/tls's 5s
	// closeTimeout when the peer of an unbuffered pipe is also closing instead
	// of reading. Closing the pipes also unblocks the client on a failed
	// handshake, so the wait below cannot hang.
	serverConn.Close()
	clientConn.Close()
	<-done
	return state.CipherSuite, err
}

// TestLegacyClientHandshake is the end-to-end claim: a client offering only
// what a UPS network management card offers fails against the defaults and
// succeeds once its suite is named, without costing modern clients anything.
func TestLegacyClientHandshake(t *testing.T) {
	cert := rsaTestCert(t)
	baseServer := func(extra *ServerTLSConfig) *tls.Config {
		c := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		if extra != nil {
			c.CipherSuites = extra.CipherSuites()
		}
		return c
	}
	// The appliance's offer, reduced to the best suite in it. It negotiates
	// TLS 1.2 fine; only the cipher list is the problem.
	legacyClient := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}

	t.Run("fails on the defaults", func(t *testing.T) {
		_, err := handshake(t, baseServer(nil), legacyClient)
		if err == nil {
			t.Fatal("expected the handshake to fail without extra_cipher_suites")
		}
		if !strings.Contains(err.Error(), "no cipher suite supported by both") {
			t.Fatalf("expected a cipher suite mismatch, got: %v", err)
		}
	})

	t.Run("succeeds once the suite is named", func(t *testing.T) {
		cfg := &ServerTLSConfig{cipherSuiteIDs: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}
		suite, err := handshake(t, baseServer(cfg), legacyClient)
		if err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
		if suite != tls.TLS_RSA_WITH_AES_128_CBC_SHA {
			t.Fatalf("negotiated %s, want TLS_RSA_WITH_AES_128_CBC_SHA", tls.CipherSuiteName(suite))
		}
	})

	t.Run("modern clients are not downgraded", func(t *testing.T) {
		// crypto/tls walks its own preference order, which ranks every ECDHE
		// suite above every RSA key exchange one, so a client that offers
		// better still gets better on the very same listener.
		cfg := &ServerTLSConfig{cipherSuiteIDs: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}
		modernClient := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
		}
		suite, err := handshake(t, baseServer(cfg), modernClient)
		if err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
		if suite != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
			t.Fatalf("negotiated %s, want an ECDHE suite", tls.CipherSuiteName(suite))
		}
	})
}
