// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// ALPN identifies the DEEP V2 application protocol. V1 is not a fallback.
const ALPN = "deep/2"
const MaxClientPins = 256

// SecurityInfo describes a completed connection using the DEEP TLS factories.
// PostQuantumAuthentication describes server authentication, not client access.
// Private servers additionally authenticate clients with the same signature profile.
type SecurityInfo struct {
	TLSVersion                string `json:"tls_version"`
	KeyExchange               string `json:"key_exchange"`
	CipherSuite               string `json:"cipher_suite"`
	Authentication            string `json:"authentication"`
	PostQuantumKeyExchange    bool   `json:"post_quantum_key_exchange"`
	PostQuantumAuthentication bool   `json:"post_quantum_authentication"`
}

// GenerateIdentity creates a self-signed ML-DSA-65 server identity. The returned
// pin is SHA-256 of the DER SubjectPublicKeyInfo, distributed through a trusted
// adapter configuration independently of the connection being authenticated.
func GenerateIdentity(authority string, validFor time.Duration) (certPEM, keyPEM []byte, pin string, err error) {
	return generateIdentity(authority, validFor, x509.ExtKeyUsageServerAuth)
}

// GenerateClientIdentity creates a separate, client-authentication-only identity.
// The authority names the client; its SPKI pin, not its name, grants access.
func GenerateClientIdentity(authority string, validFor time.Duration) (certPEM, keyPEM []byte, pin string, err error) {
	return generateIdentity(authority, validFor, x509.ExtKeyUsageClientAuth)
}

func generateIdentity(authority string, validFor time.Duration, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte, pin string, err error) {
	if err = ValidateAuthority(authority); err != nil {
		return nil, nil, "", err
	}
	if validFor <= 0 {
		return nil, nil, "", errors.New("identity validity must be positive")
	}
	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate identity: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate certificate serial: %w", err)
	}
	serial.Add(serial, big.NewInt(1))
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: authority},
		DNSNames: []string{authority}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(validFor),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.PublicKey(), privateKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("create identity certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("encode identity key: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, "", err
	}
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), hex.EncodeToString(digest[:]), nil
}

// IdentityPin returns the SPKI pin of a single ML-DSA-65 certificate. It does not
// grant trust or validate a certificate's role, lifetime, or private key.
func IdentityPin(cert tls.Certificate) (string, error) {
	leaf, err := identityLeaf(cert)
	if err != nil {
		return "", err
	}
	if err := validateIdentityKey(leaf); err != nil {
		return "", err
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(digest[:]), nil
}

func identityLeaf(cert tls.Certificate) (*x509.Certificate, error) {
	if len(cert.Certificate) != 1 {
		return nil, errors.New("DEEP V2 requires exactly one self-signed identity certificate")
	}
	// Parse DER rather than trusting a caller-supplied, possibly inconsistent Leaf.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse DEEP identity: %w", err)
	}
	return leaf, nil
}

// ValidateServerIdentity validates a local server certificate, private key, and name.
func ValidateServerIdentity(cert tls.Certificate, authority string) error {
	if err := ValidateAuthority(authority); err != nil {
		return err
	}
	return validateLocalIdentity(cert, authority, x509.ExtKeyUsageServerAuth)
}

// ValidateClientIdentity validates a local client-only certificate and private key.
func ValidateClientIdentity(cert tls.Certificate) error {
	return validateLocalIdentity(cert, "", x509.ExtKeyUsageClientAuth)
}

func validateLocalIdentity(cert tls.Certificate, authority string, usage x509.ExtKeyUsage) error {
	leaf, err := identityLeaf(cert)
	if err != nil {
		return err
	}
	if err := validateIdentity(leaf, authority, usage); err != nil {
		return err
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok || signer == nil {
		return errors.New("DEEP identity requires a signing private key")
	}
	key, ok := signer.Public().(*mldsa.PublicKey)
	if !ok || key == nil || key.Parameters() != mldsa.MLDSA65() || !key.Equal(leaf.PublicKey) {
		return errors.New("DEEP identity private key does not match its ML-DSA-65 certificate")
	}
	return nil
}

func validateIdentityKey(leaf *x509.Certificate) error {
	key, ok := leaf.PublicKey.(*mldsa.PublicKey)
	if !ok || key == nil || key.Parameters() != mldsa.MLDSA65() {
		return errors.New("DEEP V2 requires an ML-DSA-65 identity; classical authentication is forbidden")
	}
	return nil
}

func validateIdentity(leaf *x509.Certificate, authority string, usage x509.ExtKeyUsage) error {
	if err := validateIdentityKey(leaf); err != nil {
		return err
	}
	if leaf.SignatureAlgorithm != x509.MLDSA65 || !bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		return errors.New("DEEP identity must be self-signed with ML-DSA-65")
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		return fmt.Errorf("DEEP identity self-signature: %w", err)
	}
	if !leaf.BasicConstraintsValid || leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != usage || len(leaf.UnknownExtKeyUsage) != 0 {
		return errors.New("DEEP identity has an invalid certificate role or key usage")
	}
	if len(leaf.UnhandledCriticalExtensions) != 0 {
		return errors.New("DEEP identity contains an unsupported critical extension")
	}
	if len(leaf.DNSNames) != 1 || ValidateAuthority(leaf.DNSNames[0]) != nil ||
		len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		return errors.New("DEEP identity requires one canonical node.network DNS name")
	}
	if authority != "" && leaf.DNSNames[0] != authority {
		return errors.New("DEEP identity authority mismatch")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return errors.New("DEEP identity is outside its validity period")
	}
	return nil
}

// ServerTLSConfig creates an explicitly PUBLIC server: every client may fetch.
// Private servers must use ServerTLSConfigWithClientPins. Invalid identities
// fail every handshake; use ValidateServerIdentity for an early startup error.
func ServerTLSConfig(cert tls.Certificate) *tls.Config {
	config := securityTLSConfig()
	cert.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.MLDSA65}
	if leaf, err := identityLeaf(cert); err == nil {
		cert.Leaf = leaf
	}
	config.Certificates = []tls.Certificate{cert}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if err := verifySecurityProfile(state); err != nil {
			return err
		}
		// Recheck each handshake, including expiry during a long-running process.
		if state.ServerName == "" {
			return errors.New("DEEP requires an authority in TLS SNI")
		}
		return ValidateServerIdentity(cert, state.ServerName)
	}
	return config
}

// ServerTLSConfigWithClientPins requires mutual TLS with a bounded, explicit
// allowlist of client SPKI pins. No public-PKI client trust is implied.
func ServerTLSConfigWithClientPins(cert tls.Certificate, pins []string) (*tls.Config, error) {
	if err := validateLocalIdentity(cert, "", x509.ExtKeyUsageServerAuth); err != nil {
		return nil, err
	}
	if len(pins) == 0 || len(pins) > MaxClientPins {
		return nil, fmt.Errorf("private servers require 1 to %d trusted client pins", MaxClientPins)
	}
	trusted := make([][]byte, 0, len(pins))
	seen := make(map[string]bool)
	for _, pin := range pins {
		digest, err := decodeIdentityPin(pin)
		if err != nil {
			return nil, err
		}
		if seen[string(digest)] {
			return nil, errors.New("duplicate trusted client pin")
		}
		seen[string(digest)] = true
		trusted = append(trusted, digest)
	}
	config := ServerTLSConfig(cert)
	verifyServer := config.VerifyConnection
	// RequireAnyClientCert bypasses only CA-chain trust. The callback requires a
	// pinned, valid, role-specific certificate. TLS verifies CertificateVerify,
	// proving possession of the private key, before the handshake completes.
	config.ClientAuth = tls.RequireAnyClientCert
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if err := verifyServer(state); err != nil {
			return err
		}
		if len(state.PeerCertificates) != 1 {
			return errors.New("DEEP requires one pinned client identity")
		}
		leaf := state.PeerCertificates[0]
		digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		matched := 0
		for _, expected := range trusted {
			matched |= subtle.ConstantTimeCompare(expected, digest[:])
		}
		if matched != 1 {
			return errors.New("DEEP client identity is not authorized")
		}
		return validateIdentity(leaf, "", x509.ExtKeyUsageClientAuth)
	}
	return config, nil
}

// ClientTLSConfig authenticates the exact server authority using a trusted SPKI
// pin. Set Certificates to a validated client identity for a private server.
// The mandatory callback replaces public Web PKI, not authentication.
func ClientTLSConfig(authority, pin string) (*tls.Config, error) {
	if err := ValidateAuthority(authority); err != nil {
		return nil, err
	}
	expected, err := decodeIdentityPin(pin)
	if err != nil {
		return nil, err
	}
	config := securityTLSConfig()
	config.ServerName = authority
	config.InsecureSkipVerify = true
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if err := verifySecurityProfile(state); err != nil {
			return err
		}
		if len(state.PeerCertificates) != 1 {
			return errors.New("DEEP server must present exactly one identity certificate")
		}
		leaf := state.PeerCertificates[0]
		digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(expected, digest[:]) != 1 {
			return errors.New("DEEP server identity pin mismatch")
		}
		return validateIdentity(leaf, authority, x509.ExtKeyUsageServerAuth)
	}
	return config, nil
}

func decodeIdentityPin(pin string) ([]byte, error) {
	expected, err := hex.DecodeString(pin)
	if err != nil || len(expected) != sha256.Size {
		return nil, errors.New("identity pin must contain exactly 64 hexadecimal characters")
	}
	return expected, nil
}

func securityTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{ALPN},
		SessionTicketsDisabled: true,
	}
}

func verifySecurityProfile(state tls.ConnectionState) error {
	if state.Version != tls.VersionTLS13 {
		return errors.New("DEEP V2 requires TLS 1.3")
	}
	if state.CurveID != tls.X25519MLKEM768 {
		return errors.New("DEEP V2 requires X25519MLKEM768; classical fallback is forbidden")
	}
	if state.NegotiatedProtocol != ALPN {
		return errors.New("DEEP V2 ALPN was not negotiated")
	}
	if state.DidResume {
		return errors.New("DEEP V2 requires a fresh authenticated handshake")
	}
	return nil
}

// InspectSecurity requires a completed handshake made using DEEP's TLS factories.
// CurveID establishes only key exchange. Authentication comes from mandatory
// ML-DSA-65 identity validation and Go TLS's CertificateVerify verification.
// A public server has no client certificate; its own identity was checked by
// ServerTLSConfig and is not exposed in ConnectionState.PeerCertificates.
func InspectSecurity(state tls.ConnectionState) (SecurityInfo, error) {
	if !state.HandshakeComplete {
		return SecurityInfo{}, errors.New("DEEP TLS handshake is incomplete")
	}
	if err := verifySecurityProfile(state); err != nil {
		return SecurityInfo{}, err
	}
	for _, leaf := range state.PeerCertificates {
		if err := validateIdentityKey(leaf); err != nil {
			return SecurityInfo{}, err
		}
	}
	return SecurityInfo{
		TLSVersion: tls.VersionName(state.Version), KeyExchange: state.CurveID.String(),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite), Authentication: "ML-DSA-65",
		PostQuantumKeyExchange: true, PostQuantumAuthentication: true,
	}, nil
}
