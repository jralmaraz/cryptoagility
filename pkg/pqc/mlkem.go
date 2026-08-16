// Package pqc implements post-quantum cryptographic primitives following
// NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).
package pqc

import (
	"crypto/mlkem"
	"encoding/base64"
	"fmt"
)

// ML-KEM-768 parameter sizes (NIST FIPS 203, §7).
const (
	MLKEM768EncapKeyBytes = 1184 // public encapsulation key
	MLKEM768DecapKeyBytes = 2400 // private decapsulation key
	MLKEM768CiphertextBytes = 1088
	MLKEM768SharedSecretBytes = 32
)

// MLKEM768 holds an ML-KEM-768 decapsulation (private) key.
type MLKEM768 struct {
	dk *mlkem.DecapsulationKey768
}

// GenerateMLKEM768 creates a new ML-KEM-768 key pair.
func GenerateMLKEM768() (*MLKEM768, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("ml-kem-768 keygen: %w", err)
	}
	return &MLKEM768{dk: dk}, nil
}

// EncapsulationKey returns the public encapsulation key bytes (1184 bytes).
func (k *MLKEM768) EncapsulationKey() []byte {
	return k.dk.EncapsulationKey().Bytes()
}

// Encapsulate generates a ciphertext and shared secret from a serialised
// public encapsulation key. The shared secret is known only to the sender
// (until the recipient decapsulates).
func Encapsulate(encapKey []byte) (ciphertext, sharedSecret []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey768(encapKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse encapsulation key: %w", err)
	}
	// crypto/mlkem returns (sharedKey, ciphertext) — note the order.
	ss, ct := ek.Encapsulate()
	return ct, ss, nil
}

// Decapsulate recovers the shared secret from a ciphertext using the
// private decapsulation key.
func (k *MLKEM768) Decapsulate(ciphertext []byte) ([]byte, error) {
	ss, err := k.dk.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ml-kem-768 decapsulate: %w", err)
	}
	return ss, nil
}

// Summary returns display-ready metadata for the demo.
func (k *MLKEM768) Summary() map[string]interface{} {
	ekBytes := k.EncapsulationKey()
	return map[string]interface{}{
		"algorithm":           "ML-KEM-768",
		"standard":            "NIST FIPS 203",
		"security_level":      3,
		"quantum_safe":        true,
		"encap_key_bytes":     MLKEM768EncapKeyBytes,
		"ciphertext_bytes":    MLKEM768CiphertextBytes,
		"shared_secret_bytes": MLKEM768SharedSecretBytes,
		"encap_key_b64_prefix": base64.RawURLEncoding.EncodeToString(ekBytes[:12]) + "...",
	}
}
