package deep

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func securityTestIdentity(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	certPEM, keyPEM, pin, err := GenerateIdentity("node.alpha", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert, pin
}

type securityHandshakeResult struct {
	state tls.ConnectionState
	err   error
}

// Complete a real loopback TCP/TLS handshake without sending DEEP bytes.
func securityHandshake(t *testing.T, serverConfig, clientConfig *tls.Config) (securityHandshakeResult, securityHandshakeResult) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverResult := make(chan securityHandshakeResult, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverResult <- securityHandshakeResult{err: err}
			return
		}
		defer raw.Close()
		connection := tls.Server(raw, serverConfig)
		err = connection.HandshakeContext(ctx)
		serverResult <- securityHandshakeResult{state: connection.ConnectionState(), err: err}
	}()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	connection := tls.Client(raw, clientConfig)
	err = connection.HandshakeContext(ctx)
	clientResult := securityHandshakeResult{state: connection.ConnectionState(), err: err}
	select {
	case server := <-serverResult:
		return server, clientResult
	case <-ctx.Done():
		t.Fatal("server handshake did not finish")
		return securityHandshakeResult{}, clientResult
	}
}

func TestSecurityRealHybridHandshake(t *testing.T) {
	cert, pin := securityTestIdentity(t)
	client, err := ClientTLSConfig("node.alpha", pin)
	if err != nil {
		t.Fatal(err)
	}
	server, peer := securityHandshake(t, ServerTLSConfig(cert), client)
	for _, result := range []securityHandshakeResult{server, peer} {
		if result.err != nil {
			t.Fatal(result.err)
		}
		info, err := InspectSecurity(result.state)
		if err != nil {
			t.Fatal(err)
		}
		if info.KeyExchange != "X25519MLKEM768" || !info.PostQuantumKeyExchange || info.TLSVersion != "TLS 1.3" {
			t.Fatalf("unexpected negotiated security: %+v", info)
		}
		if result.state.DidResume {
			t.Fatal("DEEP V1 unexpectedly resumed a TLS session")
		}
	}
}

func TestSecurityRejectsWrongPinAndName(t *testing.T) {
	cert, pin := securityTestIdentity(t)
	for _, test := range []struct{ name, authority, pin string }{
		{"wrong pin", "node.alpha", strings.Repeat("00", sha256.Size)},
		{"wrong name", "other.alpha", pin},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := ClientTLSConfig(test.authority, test.pin)
			if err != nil {
				t.Fatal(err)
			}
			_, peer := securityHandshake(t, ServerTLSConfig(cert), client)
			if peer.err == nil {
				t.Fatal("client accepted incorrect server identity")
			}
		})
	}
}

func TestSecurityRejectsClassicalFallback(t *testing.T) {
	cert, pin := securityTestIdentity(t)
	for _, classicalSide := range []string{"client", "server"} {
		t.Run(classicalSide, func(t *testing.T) {
			client, err := ClientTLSConfig("node.alpha", pin)
			if err != nil {
				t.Fatal(err)
			}
			server := ServerTLSConfig(cert)
			if classicalSide == "client" {
				client.CurvePreferences = []tls.CurveID{tls.X25519}
			} else {
				server.CurvePreferences = []tls.CurveID{tls.X25519}
			}
			serverResult, clientResult := securityHandshake(t, server, client)
			if serverResult.err == nil || clientResult.err == nil {
				t.Fatal("classical-only peer was accepted")
			}
		})
	}
}

func TestSecurityRejectsMissingOrWrongALPN(t *testing.T) {
	cert, pin := securityTestIdentity(t)
	for _, side := range []string{"client", "server"} {
		for _, protocol := range []string{"", "unrelated/1"} {
			t.Run(side+"/"+protocol, func(t *testing.T) {
				client, err := ClientTLSConfig("node.alpha", pin)
				if err != nil {
					t.Fatal(err)
				}
				server := ServerTLSConfig(cert)
				changed := server
				if side == "client" {
					changed = client
				}
				changed.NextProtos = nil
				if protocol != "" {
					changed.NextProtos = []string{protocol}
				}
				serverResult, clientResult := securityHandshake(t, server, client)
				if serverResult.err == nil || clientResult.err == nil {
					t.Fatal("peer without DEEP ALPN was accepted")
				}
			})
		}
	}
}

func TestSecurityRejectsLegacyTLS(t *testing.T) {
	cert, pin := securityTestIdentity(t)
	client, err := ClientTLSConfig("node.alpha", pin)
	if err != nil {
		t.Fatal(err)
	}
	server := ServerTLSConfig(cert)
	server.MinVersion, server.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	server.CurvePreferences = []tls.CurveID{tls.X25519}
	serverResult, clientResult := securityHandshake(t, server, client)
	if serverResult.err == nil || clientResult.err == nil {
		t.Fatal("TLS 1.2 was accepted")
	}
}

func TestSecurityExplicitHybridIgnoresDefaultDisable(t *testing.T) {
	t.Setenv("GODEBUG", "tlsmlkem=0")
	TestSecurityRealHybridHandshake(t)
}

func TestSecurityRejectsInvalidInputs(t *testing.T) {
	for _, authority := range []string{"", "*.alpha", "node.alpha:443", "node..alpha", "-node.alpha", "node.alpha/", "nøde.alpha", strings.Repeat("a", 64) + ".alpha"} {
		if _, _, _, err := GenerateIdentity(authority, time.Hour); err == nil {
			t.Errorf("accepted invalid authority %q", authority)
		}
		if _, err := ClientTLSConfig(authority, strings.Repeat("00", sha256.Size)); err == nil {
			t.Errorf("client accepted invalid authority %q", authority)
		}
	}
	for _, pin := range []string{"", "00", strings.Repeat("0", 63), strings.Repeat("z", 64)} {
		if _, err := ClientTLSConfig("node.alpha", pin); err == nil {
			t.Errorf("accepted invalid pin %q", pin)
		}
	}
	if _, _, _, err := GenerateIdentity("node.alpha", 0); err == nil {
		t.Error("accepted zero validity")
	}
}

func TestSecurityPinAndCertificateMetadata(t *testing.T) {
	certPEM, _, pin, err := GenerateIdentity("node.alpha", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if pin != hex.EncodeToString(digest[:]) {
		t.Fatal("pin does not hash DER SubjectPublicKeyInfo")
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		t.Fatal("identity key is not Ed25519")
	}
	if err := cert.VerifyHostname("node.alpha"); err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityRejectsInvalidCertificateMetadata(t *testing.T) {
	for _, kind := range []string{"expired", "future", "ecdsa"} {
		t.Run(kind, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			var pub, priv any = public, private
			now := time.Now()
			certTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(42), DNSNames: []string{"node.alpha"},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature,
			}
			switch kind {
			case "expired":
				certTemplate.NotBefore, certTemplate.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
			case "future":
				certTemplate.NotBefore, certTemplate.NotAfter = now.Add(time.Hour), now.Add(2*time.Hour)
			case "ecdsa":
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				pub, priv = &key.PublicKey, key
			}
			der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, pub, priv)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			client, err := ClientTLSConfig("node.alpha", hex.EncodeToString(digest[:]))
			if err != nil {
				t.Fatal(err)
			}
			cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
			_, result := securityHandshake(t, ServerTLSConfig(cert), client)
			if result.err == nil {
				t.Fatal("client accepted invalid identity metadata")
			}
		})
	}
}

func TestSecurityInspectRejectsUnverifiedProfile(t *testing.T) {
	valid := tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		CurveID: tls.X25519MLKEM768, NegotiatedProtocol: ALPN}
	for _, change := range []func(*tls.ConnectionState){
		func(s *tls.ConnectionState) { s.HandshakeComplete = false },
		func(s *tls.ConnectionState) { s.Version = tls.VersionTLS12 },
		func(s *tls.ConnectionState) { s.CurveID = tls.X25519 },
		func(s *tls.ConnectionState) { s.NegotiatedProtocol = "" },
	} {
		state := valid
		change(&state)
		if _, err := InspectSecurity(state); err == nil {
			t.Errorf("accepted invalid security state: %+v", state)
		}
	}
}
