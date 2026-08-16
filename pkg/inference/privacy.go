// Package inference implements a pedagogical simulation of homomorphic
// encryption for privacy-preserving AI inference.
//
// Real HE schemes (CKKS for floats, BFV/BGV for integers, TFHE for boolean
// circuits) use lattice-based mathematics and are implemented by libraries
// such as Microsoft SEAL, OpenFHE, and Google's HEIR project.
//
// This package uses a toy additive scheme that demonstrates the key property:
// computation on ciphertexts yields results equal to computation on
// plaintexts — the server never sees the plaintext inputs.
package inference

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
)

// HEKey is the secret key for the simulated additive HE scheme.
type HEKey struct {
	id string // display identifier only
}

// GenerateHEKey creates a new HE key.
func GenerateHEKey() *HEKey {
	var buf [4]byte
	rand.Read(buf[:])
	return &HEKey{id: fmt.Sprintf("he-key-%08x", binary.BigEndian.Uint32(buf[:]))}
}

// ID returns the key identifier for display.
func (k *HEKey) ID() string { return k.id }

// EncryptedInt is a homomorphically encrypted integer.
// Invariant: Decrypt() == original plaintext after any Add/Scale chain.
type EncryptedInt struct {
	// cipher = plaintext + mask  (mask known only to key holder)
	cipher int64
	mask   int64
}

// Encrypt encrypts an integer value.
// In real LWE-based HE: c = m·Δ + noise·key mod q.
// Here: c = m + mask where mask is a random 20-bit value.
func (k *HEKey) Encrypt(v int64) *EncryptedInt {
	var buf [8]byte
	rand.Read(buf[:])
	mask := int64(binary.LittleEndian.Uint64(buf[:])) & ((1 << 20) - 1)
	return &EncryptedInt{cipher: v + mask, mask: mask}
}

// Decrypt recovers the plaintext from a ciphertext.
func (e *EncryptedInt) Decrypt() int64 {
	return e.cipher - e.mask
}

// Add computes Enc(a) + Enc(b) = Enc(a+b) without decrypting.
// The homomorphic property: masks combine additively.
func (a *EncryptedInt) Add(b *EncryptedInt) *EncryptedInt {
	return &EncryptedInt{
		cipher: a.cipher + b.cipher,
		mask:   a.mask + b.mask,
	}
}

// Scale computes n × Enc(v) = Enc(n×v) without decrypting.
func (e *EncryptedInt) Scale(n int64) *EncryptedInt {
	return &EncryptedInt{cipher: e.cipher * n, mask: e.mask * n}
}

// Ciphertext returns the raw ciphertext value (opaque to the server).
func (e *EncryptedInt) Ciphertext() int64 { return e.cipher }

// InferenceResult is the server-side output of running a model over
// encrypted inputs.
type InferenceResult struct {
	// EncryptedOutput is the dot-product ciphertext — client decrypts this.
	EncryptedOutput *EncryptedInt
	// Plaintext is the decrypted result (populated only by the client).
	Plaintext int64
	// Steps records the computation trace for the demo.
	Steps []string
}

// RunInference computes the weighted dot product of encrypted inputs and
// plaintext weights — simulating a single inference layer.
//
// The server holds weights (the model); the client sends encrypted inputs.
// The server returns an encrypted output; the client decrypts locally.
//
// Weights are scaled ×1000 to integers for fixed-point arithmetic.
func RunInference(encInputs []*EncryptedInt, weights []float64) (*InferenceResult, error) {
	if len(encInputs) == 0 {
		return nil, fmt.Errorf("no inputs")
	}
	if len(encInputs) != len(weights) {
		return nil, fmt.Errorf("inputs/weights length mismatch: %d vs %d", len(encInputs), len(weights))
	}

	res := &InferenceResult{}
	acc := encInputs[0].Scale(int64(math.Round(weights[0] * 1000)))
	res.Steps = append(res.Steps,
		fmt.Sprintf("step 0: enc(%d) × %.3f = enc(%d) [ciphertext=%d]",
			encInputs[0].Decrypt(), weights[0],
			encInputs[0].Decrypt()*int64(math.Round(weights[0]*1000)),
			acc.Ciphertext()))

	for i := 1; i < len(encInputs); i++ {
		term := encInputs[i].Scale(int64(math.Round(weights[i] * 1000)))
		res.Steps = append(res.Steps,
			fmt.Sprintf("step %d: enc(%d) × %.3f = enc(%d) [ciphertext=%d]",
				i, encInputs[i].Decrypt(), weights[i],
				encInputs[i].Decrypt()*int64(math.Round(weights[i]*1000)),
				term.Ciphertext()))
		acc = acc.Add(term)
	}

	res.EncryptedOutput = acc
	// Plaintext stays 0 until client decrypts.
	return res, nil
}

// DecryptResult decrypts the inference output and divides by the
// fixed-point scale factor (1000) to recover the float result.
func DecryptResult(r *InferenceResult, key *HEKey) float64 {
	r.Plaintext = r.EncryptedOutput.Decrypt()
	return float64(r.Plaintext) / 1000.0
}
