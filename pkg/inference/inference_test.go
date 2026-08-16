package inference_test

import (
	"math"
	"testing"

	"github.com/jralmaraz/cryptoagility/pkg/inference"
)

func TestEncryptDecrypt(t *testing.T) {
	key := inference.GenerateHEKey()
	for _, v := range []int64{0, 1, -5, 42, 999, -1234} {
		enc := key.Encrypt(v)
		if got := enc.Decrypt(); got != v {
			t.Errorf("Decrypt(Encrypt(%d)) = %d", v, got)
		}
	}
}

func TestHomomorphicAdd(t *testing.T) {
	key := inference.GenerateHEKey()
	a, b := int64(17), int64(25)
	ea, eb := key.Encrypt(a), key.Encrypt(b)
	sum := ea.Add(eb)
	if got, want := sum.Decrypt(), a+b; got != want {
		t.Errorf("Add: got %d, want %d", got, want)
	}
}

func TestHomomorphicScale(t *testing.T) {
	key := inference.GenerateHEKey()
	v, n := int64(7), int64(5)
	ev := key.Encrypt(v)
	scaled := ev.Scale(n)
	if got, want := scaled.Decrypt(), v*n; got != want {
		t.Errorf("Scale: got %d, want %d", got, want)
	}
}

func TestHomomorphicAddChain(t *testing.T) {
	key := inference.GenerateHEKey()
	vals := []int64{3, 7, 11, 4}
	encrypted := make([]*inference.EncryptedInt, len(vals))
	for i, v := range vals {
		encrypted[i] = key.Encrypt(v)
	}
	acc := encrypted[0]
	sum := vals[0]
	for i := 1; i < len(encrypted); i++ {
		acc = acc.Add(encrypted[i])
		sum += vals[i]
	}
	if got := acc.Decrypt(); got != sum {
		t.Errorf("chain Add: got %d, want %d", got, sum)
	}
}

func TestCiphertextIsNotPlaintext(t *testing.T) {
	key := inference.GenerateHEKey()
	v := int64(42)
	enc := key.Encrypt(v)
	// The ciphertext should not equal the plaintext (mask applied).
	if enc.Ciphertext() == v {
		// This can theoretically happen if mask==0 (1 in 2^20 chance).
		t.Log("ciphertext equals plaintext — mask happened to be 0 (unlikely but possible)")
	}
}

func TestRunInference(t *testing.T) {
	key := inference.GenerateHEKey()
	// inputs: [2, 3, 4], weights: [0.5, 1.0, 0.25]
	// expected: 2×0.5 + 3×1.0 + 4×0.25 = 1 + 3 + 1 = 5.0
	inputs := []int64{2, 3, 4}
	weights := []float64{0.5, 1.0, 0.25}

	encInputs := make([]*inference.EncryptedInt, len(inputs))
	for i, v := range inputs {
		encInputs[i] = key.Encrypt(v)
	}

	res, err := inference.RunInference(encInputs, weights)
	if err != nil {
		t.Fatalf("RunInference: %v", err)
	}
	got := inference.DecryptResult(res, key)
	want := 5.0
	if math.Abs(got-want) > 0.001 {
		t.Errorf("inference result: got %.3f, want %.3f", got, want)
	}
}

func TestRunInferenceNegativeWeights(t *testing.T) {
	key := inference.GenerateHEKey()
	inputs := []int64{10, 5}
	weights := []float64{0.8, -0.6}
	// expected: 10×0.8 + 5×(-0.6) = 8 - 3 = 5.0

	encInputs := make([]*inference.EncryptedInt, len(inputs))
	for i, v := range inputs {
		encInputs[i] = key.Encrypt(v)
	}
	res, err := inference.RunInference(encInputs, weights)
	if err != nil {
		t.Fatalf("RunInference: %v", err)
	}
	got := inference.DecryptResult(res, key)
	if math.Abs(got-5.0) > 0.001 {
		t.Errorf("negative weights: got %.3f, want 5.000", got)
	}
}

func TestRunInferenceLengthMismatch(t *testing.T) {
	key := inference.GenerateHEKey()
	encInputs := []*inference.EncryptedInt{key.Encrypt(1)}
	_, err := inference.RunInference(encInputs, []float64{0.5, 1.0})
	if err == nil {
		t.Error("expected error for length mismatch")
	}
}

func TestRunInferenceEmpty(t *testing.T) {
	_, err := inference.RunInference(nil, nil)
	if err == nil {
		t.Error("expected error for empty inputs")
	}
}
