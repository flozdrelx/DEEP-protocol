// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

var invalidSecurityIdentityKinds = []string{
	"expired", "future", "ed25519", "ecdsa", "mldsa44", "mldsa87", "wrong-role", "dual-role",
	"no-usage", "bad-key-usage", "unknown-critical", "ca", "no-constraints", "wildcard", "uppercase",
	"multiple-names", "missing-name", "extra-ip", "invalid-signature", "other-signer", "bad-chain",
}

func malformedSecurityIdentity(t *testing.T, usage x509.ExtKeyUsage, kind string) (tls.Certificate, string) {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	var signer crypto.Signer = key
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "node.alpha"}, DNSNames: []string{"node.alpha"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage}, BasicConstraintsValid: true,
	}
	switch kind {
	case "expired":
		template.NotBefore, template.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	case "future":
		template.NotBefore, template.NotAfter = now.Add(time.Hour), now.Add(2*time.Hour)
	case "ed25519":
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "mldsa44":
		signer, err = mldsa.GenerateKey(mldsa.MLDSA44())
	case "mldsa87":
		signer, err = mldsa.GenerateKey(mldsa.MLDSA87())
	case "wrong-role":
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		if usage == x509.ExtKeyUsageClientAuth {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
	case "dual-role":
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	case "no-usage":
		template.ExtKeyUsage = nil
	case "bad-key-usage":
		template.KeyUsage = x509.KeyUsageKeyEncipherment
	case "unknown-critical":
		template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 999}, Critical: true, Value: []byte{5, 0}}}
	case "ca":
		template.IsCA = true
	case "no-constraints":
		template.BasicConstraintsValid = false
	case "wildcard":
		template.DNSNames = []string{"*.alpha"}
	case "uppercase":
		template.DNSNames = []string{"NODE.alpha"}
	case "multiple-names":
		template.DNSNames = []string{"node.alpha", "second.alpha"}
	case "missing-name":
		template.DNSNames = nil
	case "extra-ip":
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	if err != nil {
		t.Fatal(err)
	}
	issuer := signer
	if kind == "other-signer" {
		issuer, err = mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			t.Fatal(err)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), issuer)
	if err != nil {
		t.Fatal(err)
	}
	if kind == "invalid-signature" {
		der[len(der)-1] ^= 1
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: signer, Leaf: leaf}
	if kind == "bad-chain" {
		cert.Certificate = append(cert.Certificate, der)
	}
	return cert, hex.EncodeToString(digest[:])
}

func securityTestClientIdentity(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	certPEM, keyPEM, pin, err := GenerateClientIdentity("client.alpha", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert, pin
}

func TestSecurityMutualTLS(t *testing.T) {
	serverIdentity, serverPin := securityTestIdentity(t)
	clientIdentity, clientPin := securityTestClientIdentity(t)
	server, err := ServerTLSConfigWithClientPins(serverIdentity, []string{clientPin})
	if err != nil {
		t.Fatal(err)
	}
	client, err := ClientTLSConfig("node.alpha", serverPin)
	if err != nil {
		t.Fatal(err)
	}
	client.Certificates = []tls.Certificate{clientIdentity}
	ours, theirs := securityHandshake(t, server, client)
	for _, result := range []securityHandshakeResult{ours, theirs} {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if len(result.state.PeerCertificates) != 1 {
			t.Fatal("mutual TLS did not authenticate both peers")
		}
		info, err := InspectSecurity(result.state)
		if err != nil || !info.PostQuantumAuthentication || info.Authentication != "ML-DSA-65" {
			t.Fatalf("unexpected security report: %+v, %v", info, err)
		}
	}
	if err := ValidateServerIdentity(serverIdentity, "node.alpha"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateClientIdentity(clientIdentity); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityMutualTLSRejectsMissingOrUntrustedClient(t *testing.T) {
	serverIdentity, serverPin := securityTestIdentity(t)
	_, authorizedPin := securityTestClientIdentity(t)
	for _, kind := range []string{"missing", "untrusted", "server-identity"} {
		t.Run(kind, func(t *testing.T) {
			server, err := ServerTLSConfigWithClientPins(serverIdentity, []string{authorizedPin})
			if err != nil {
				t.Fatal(err)
			}
			client, err := ClientTLSConfig("node.alpha", serverPin)
			if err != nil {
				t.Fatal(err)
			}
			if kind != "missing" {
				cert, _ := securityTestClientIdentity(t)
				if kind == "server-identity" {
					cert = serverIdentity
				}
				client.Certificates = []tls.Certificate{cert}
			}
			result, _ := securityHandshake(t, server, client)
			// TLS 1.3's client may report handshake completion before receiving a
			// server-side certificate rejection. The server result is authoritative.
			if result.err == nil {
				t.Fatal("server accepted an unauthorized client")
			}
		})
	}
}

func TestSecurityMutualTLSRejectsInvalidPinnedClient(t *testing.T) {
	serverIdentity, serverPin := securityTestIdentity(t)
	for _, kind := range invalidSecurityIdentityKinds {
		t.Run(kind, func(t *testing.T) {
			cert, pin := malformedSecurityIdentity(t, x509.ExtKeyUsageClientAuth, kind)
			server, err := ServerTLSConfigWithClientPins(serverIdentity, []string{pin})
			if err != nil {
				t.Fatal(err)
			}
			client, err := ClientTLSConfig("node.alpha", serverPin)
			if err != nil {
				t.Fatal(err)
			}
			client.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
			result, _ := securityHandshake(t, server, client)
			if result.err == nil {
				t.Fatal("server accepted invalid pinned client")
			}
			if err := ValidateClientIdentity(cert); err == nil {
				t.Fatal("local validator accepted invalid client")
			}
		})
	}
}

func TestSecurityClientPinAllowlistValidation(t *testing.T) {
	cert, _ := securityTestIdentity(t)
	pin := strings.Repeat("ab", 32)
	for _, pins := range [][]string{nil, {}, {""}, {"1234"}, {strings.Repeat("z", 64)}, {pin, strings.ToUpper(pin)}, make([]string, MaxClientPins+1)} {
		if _, err := ServerTLSConfigWithClientPins(cert, pins); err == nil {
			t.Errorf("accepted invalid pin list of size %d", len(pins))
		}
	}
	if _, err := ServerTLSConfigWithClientPins(tls.Certificate{}, []string{pin}); err == nil {
		t.Fatal("accepted missing server identity")
	}
}

func TestSecurityLocalIdentityKeyAndRoleValidation(t *testing.T) {
	server, pin := securityTestIdentity(t)
	client, _ := securityTestClientIdentity(t)
	if actual, err := IdentityPin(server); err != nil || actual != pin {
		t.Fatalf("pin = %q, %v", actual, err)
	}
	if err := ValidateClientIdentity(server); err == nil {
		t.Fatal("server identity accepted as client")
	}
	if err := ValidateServerIdentity(client, "client.alpha"); err == nil {
		t.Fatal("client identity accepted as server")
	}
	if err := ValidateServerIdentity(server, "other.alpha"); err == nil {
		t.Fatal("wrong server name accepted")
	}
	for _, private := range []any{nil, client.PrivateKey} {
		changed := server
		changed.PrivateKey = private
		if err := ValidateServerIdentity(changed, "node.alpha"); err == nil {
			t.Fatal("invalid private key accepted")
		}
	}
	for _, authority := range []string{"single", "a.b.c", "NODE.alpha", "node.ALPHA"} {
		if _, _, _, err := GenerateIdentity(authority, time.Hour); err == nil {
			t.Errorf("accepted %q", authority)
		}
		if _, _, _, err := GenerateClientIdentity(authority, time.Hour); err == nil {
			t.Errorf("accepted client %q", authority)
		}
		if _, err := ClientTLSConfig(authority, pin); err == nil {
			t.Errorf("accepted TLS name %q", authority)
		}
	}
	if _, _, _, err := GenerateClientIdentity("client.alpha", 0); err == nil {
		t.Fatal("accepted zero client validity")
	}
	if _, err := IdentityPin(tls.Certificate{}); err == nil {
		t.Fatal("accepted missing certificate")
	}
}

func TestSecurityPublicServerRejectsInvalidLocalIdentity(t *testing.T) {
	for _, kind := range invalidSecurityIdentityKinds {
		t.Run(kind, func(t *testing.T) {
			cert, _ := malformedSecurityIdentity(t, x509.ExtKeyUsageServerAuth, kind)
			if err := ValidateServerIdentity(cert, "node.alpha"); err == nil {
				t.Fatal("accepted invalid server identity")
			}
		})
	}
}

func TestSecurityRejectsMissingAndMismatchedSNI(t *testing.T) {
	cert, _ := securityTestIdentity(t)
	for _, name := range []string{"", "other.alpha", "NODE.alpha"} {
		t.Run(name, func(t *testing.T) {
			client := securityTLSConfig()
			client.InsecureSkipVerify = true
			client.ServerName = name
			ours, _ := securityHandshake(t, ServerTLSConfig(cert), client)
			if ours.err == nil {
				t.Fatal("server accepted invalid SNI")
			}
		})
	}
}

func TestSecurityPinnedIdentityRequiresPrivateKeyPossession(t *testing.T) {
	serverIdentity, serverPin := securityTestIdentity(t)
	authorized, authorizedPin := securityTestClientIdentity(t)
	impostor, _ := securityTestClientIdentity(t)
	// Replaying an authorized public certificate is not enough: CertificateVerify
	// must be signed by its own private key, which the impostor does not possess.
	authorized.PrivateKey = impostor.PrivateKey
	server, err := ServerTLSConfigWithClientPins(serverIdentity, []string{authorizedPin})
	if err != nil {
		t.Fatal(err)
	}
	client, err := ClientTLSConfig("node.alpha", serverPin)
	if err != nil {
		t.Fatal(err)
	}
	client.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &authorized, nil }
	result, _ := securityHandshake(t, server, client)
	if result.err == nil {
		t.Fatal("pin-only impersonation bypassed proof of private-key possession")
	}
}

func TestSecurityIgnoresForgedCachedCertificateLeaf(t *testing.T) {
	good, _ := securityTestIdentity(t)
	bad, _ := malformedSecurityIdentity(t, x509.ExtKeyUsageServerAuth, "expired")
	bad.Leaf = good.Leaf
	if err := ValidateServerIdentity(bad, "node.alpha"); err == nil {
		t.Fatal("trusted cached Leaf instead of certificate DER")
	}
}
