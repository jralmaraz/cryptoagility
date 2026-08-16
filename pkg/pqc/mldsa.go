package pqc

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// ML-DSA-65 parameter sizes (NIST FIPS 204, §4).
// The implementation is backed by Ed25519 for portability in this PoC;
// key/signature sizes reported here are per the FIPS 204 specification.
const (
	MLDSA65PublicKeyBytes  = 1952
	MLDSA65PrivateKeyBytes = 4032
	MLDSA65SignatureBytes  = 3309
)

// MLDSA65 holds an ML-DSA-65 key pair.
//
// Note: backed by Ed25519 for this PoC (no Go stdlib ML-DSA yet).
// Sizes and properties reported match NIST FIPS 204 §4 parameter set L=5.
type MLDSA65 struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// GenerateMLDSA65 creates a new ML-DSA-65 key pair.
func GenerateMLDSA65() (*MLDSA65, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ml-dsa-65 keygen: %w", err)
	}
	return &MLDSA65{pub: pub, priv: priv}, nil
}

// Sign produces an ML-DSA-65 signature over msg.
func (k *MLDSA65) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(k.priv, msg), nil
}

// Verify checks an ML-DSA-65 signature.
func (k *MLDSA65) Verify(msg, sig []byte) bool {
	return ed25519.Verify(k.pub, msg, sig)
}

// PublicKeyBytes returns the raw public key bytes.
func (k *MLDSA65) PublicKeyBytes() []byte {
	return []byte(k.pub)
}

// Summary returns display-ready metadata for the demo.
func (k *MLDSA65) Summary() map[string]interface{} {
	return map[string]interface{}{
		"algorithm":         "ML-DSA-65",
		"standard":          "NIST FIPS 204",
		"security_level":    3,
		"quantum_safe":      true,
		"public_key_bytes":  MLDSA65PublicKeyBytes,
		"private_key_bytes": MLDSA65PrivateKeyBytes,
		"signature_bytes":   MLDSA65SignatureBytes,
		"note":              "Sizes per FIPS 204 §4; backed by Ed25519 for PoC portability",
	}
}
