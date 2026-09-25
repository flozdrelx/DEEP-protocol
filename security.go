package deep

import (
	"crypto/ed25519"
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
	"strings"
	"time"
)

// ALPN identifies the experimental DEEP V1 application protocol.
const ALPN = "deep/1"

// SecurityInfo describes the negotiated channel, not a claim of post-quantum
// authentication. Ed25519 authentication remains classical.
type SecurityInfo struct {
	TLSVersion             string `json:"tls_version"`
	KeyExchange            string `json:"key_exchange"`
	CipherSuite            string `json:"cipher_suite"`
	Authentication         string `json:"authentication"`
	PostQuantumKeyExchange bool   `json:"post_quantum_key_exchange"`
}

// GenerateIdentity creates a self-signed Ed25519 server identity for authority.
// The returned pin is the lowercase hexadecimal SHA-256 digest of DER SPKI.
// Distribute the pin through a trusted adapter configuration, separately from
// the connection being authenticated.
func GenerateIdentity(authority string, validFor time.Duration) (certPEM, keyPEM []byte, pin string, err error) {
	if err = validateSecurityAuthority(authority); err != nil {
		return nil, nil, "", err
	}
	if validFor <= 0 {
		return nil, nil, "", errors.New("identity validity must be positive")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate identity: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate certificate serial: %w", err)
	}
	serial.Add(serial, big.NewInt(1))
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: authority},
		DNSNames:              []string{authority},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("create identity certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("encode identity key: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, "", fmt.Errorf("parse generated certificate: %w", err)
	}
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		hex.EncodeToString(digest[:]), nil
}

// ServerTLSConfig requires a fresh TLS 1.3 hybrid exchange and DEEP ALPN.
// The caller must supply the Ed25519 identity created by GenerateIdentity.
func ServerTLSConfig(cert tls.Certificate) *tls.Config {
	config := securityTLSConfig()
	config.Certificates = []tls.Certificate{cert}
	var identityErr error
	if len(cert.Certificate) == 0 {
		identityErr = errors.New("DEEP server requires an Ed25519 identity certificate")
	} else {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			identityErr = fmt.Errorf("parse DEEP server identity: %w", err)
		} else if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
			identityErr = errors.New("DEEP V1 requires an Ed25519 server identity")
		}
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if err := verifySecurityProfile(state); err != nil {
			return err
		}
		return identityErr
	}
	return config
}

// ClientTLSConfig authenticates authority using an explicitly trusted SPKI pin.
// It deliberately uses a mandatory pin verifier instead of public Web PKI roots.
func ClientTLSConfig(authority, pin string) (*tls.Config, error) {
	if err := validateSecurityAuthority(authority); err != nil {
		return nil, err
	}
	expected, err := hex.DecodeString(pin)
	if err != nil || len(expected) != sha256.Size {
		return nil, errors.New("identity pin must contain exactly 64 hexadecimal characters")
	}
	config := securityTLSConfig()
	config.ServerName = authority
	// The callback below is the trust policy: pin, hostname, lifetime and key
	// type are mandatory. There is no insecure mode or opportunistic fallback.
	config.InsecureSkipVerify = true
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if err := verifySecurityProfile(state); err != nil {
			return err
		}
		if len(state.PeerCertificates) == 0 {
			return errors.New("DEEP server did not present an identity")
		}
		leaf := state.PeerCertificates[0]
		if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
			return errors.New("DEEP V1 requires an Ed25519 server identity")
		}
		digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(expected, digest[:]) != 1 {
			return errors.New("DEEP server identity pin mismatch")
		}
		if err := leaf.VerifyHostname(authority); err != nil {
			return fmt.Errorf("DEEP server identity hostname: %w", err)
		}
		now := time.Now()
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return errors.New("DEEP server identity is outside its validity period")
		}
		return nil
	}
	return config, nil
}

func securityTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		NextProtos:             []string{ALPN},
		SessionTicketsDisabled: true,
	}
}

func verifySecurityProfile(state tls.ConnectionState) error {
	if state.Version != tls.VersionTLS13 {
		return errors.New("DEEP V1 requires TLS 1.3")
	}
	if state.CurveID != tls.X25519MLKEM768 {
		return errors.New("DEEP V1 requires X25519MLKEM768; classical fallback is forbidden")
	}
	if state.NegotiatedProtocol != ALPN {
		return errors.New("DEEP V1 ALPN was not negotiated")
	}
	return nil
}

// InspectSecurity must be called after a successful HandshakeContext and before
// application data is exchanged. Callbacks cannot require HandshakeComplete.
func InspectSecurity(state tls.ConnectionState) (SecurityInfo, error) {
	if !state.HandshakeComplete {
		return SecurityInfo{}, errors.New("DEEP TLS handshake is incomplete")
	}
	if err := verifySecurityProfile(state); err != nil {
		return SecurityInfo{}, err
	}
	return SecurityInfo{
		TLSVersion:             tls.VersionName(state.Version),
		KeyExchange:            state.CurveID.String(),
		CipherSuite:            tls.CipherSuiteName(state.CipherSuite),
		Authentication:         "Ed25519 (classical)",
		PostQuantumKeyExchange: true,
	}, nil
}

func validateSecurityAuthority(authority string) error {
	if authority == "" || len(authority) > 253 {
		return errors.New("identity authority must be a valid ASCII hostname")
	}
	for _, label := range strings.Split(authority, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("identity authority must be a valid ASCII hostname")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return errors.New("identity authority must be a valid ASCII hostname")
			}
		}
	}
	return nil
}
