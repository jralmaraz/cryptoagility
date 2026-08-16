package pqc_test

import (
	"bytes"
	"testing"

	"github.com/jralmaraz/cryptoagility/pkg/pqc"
)

// --- ML-KEM-768 tests ---

func TestMLKEM768Generate(t *testing.T) {
	k, err := pqc.GenerateMLKEM768()
	if err != nil {
		t.Fatalf("GenerateMLKEM768: %v", err)
	}
	ek := k.EncapsulationKey()
	if len(ek) != pqc.MLKEM768EncapKeyBytes {
		t.Errorf("encapsulation key: got %d bytes, want %d", len(ek), pqc.MLKEM768EncapKeyBytes)
	}
}

func TestMLKEM768RoundTrip(t *testing.T) {
	k, err := pqc.GenerateMLKEM768()
	if err != nil {
		t.Fatalf("GenerateMLKEM768: %v", err)
	}

	ct, ss1, err := pqc.Encapsulate(k.EncapsulationKey())
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(ct) != pqc.MLKEM768CiphertextBytes {
		t.Errorf("ciphertext: got %d bytes, want %d", len(ct), pqc.MLKEM768CiphertextBytes)
	}
	if len(ss1) != pqc.MLKEM768SharedSecretBytes {
		t.Errorf("shared secret: got %d bytes, want %d", len(ss1), pqc.MLKEM768SharedSecretBytes)
	}

	ss2, err := k.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Error("shared secrets do not match")
	}
}

func TestMLKEM768TamperedCiphertext(t *testing.T) {
	k, err := pqc.GenerateMLKEM768()
	if err != nil {
		t.Fatalf("GenerateMLKEM768: %v", err)
	}
	ct, ss1, err := pqc.Encapsulate(k.EncapsulationKey())
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	// Flip bytes in ciphertext.
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	for i := range tampered {
		tampered[i] ^= 0xFF
	}
	ss2, err := k.Decapsulate(tampered)
	// ML-KEM decapsulation is implicit rejection: it succeeds but returns
	// a different (random-looking) shared secret.
	if err != nil {
		t.Logf("decapsulate with tampered CT returned error (also acceptable): %v", err)
		return
	}
	if bytes.Equal(ss1, ss2) {
		t.Error("tampered ciphertext produced the same shared secret — should differ")
	}
}

func TestMLKEM768BadKey(t *testing.T) {
	_, _, err := pqc.Encapsulate([]byte("not a valid key"))
	if err == nil {
		t.Error("expected error for invalid encapsulation key")
	}
}

func TestMLKEM768Summary(t *testing.T) {
	k, err := pqc.GenerateMLKEM768()
	if err != nil {
		t.Fatalf("GenerateMLKEM768: %v", err)
	}
	s := k.Summary()
	if s["algorithm"] != "ML-KEM-768" {
		t.Errorf("summary algorithm: got %v", s["algorithm"])
	}
	if s["quantum_safe"] != true {
		t.Error("summary should report quantum_safe=true")
	}
}

// --- ML-DSA-65 tests ---

func TestMLDSA65Generate(t *testing.T) {
	k, err := pqc.GenerateMLDSA65()
	if err != nil {
		t.Fatalf("GenerateMLDSA65: %v", err)
	}
	if len(k.PublicKeyBytes()) == 0 {
		t.Error("empty public key")
	}
}

func TestMLDSA65SignVerify(t *testing.T) {
	k, err := pqc.GenerateMLDSA65()
	if err != nil {
		t.Fatalf("GenerateMLDSA65: %v", err)
	}
	msg := []byte("agent identity token payload")
	sig, err := k.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !k.Verify(msg, sig) {
		t.Error("Verify: valid signature rejected")
	}
}

func TestMLDSA65TamperedMessage(t *testing.T) {
	k, err := pqc.GenerateMLDSA65()
	if err != nil {
		t.Fatalf("GenerateMLDSA65: %v", err)
	}
	msg := []byte("agent identity token payload")
	sig, err := k.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0x01
	if k.Verify(tampered, sig) {
		t.Error("Verify: tampered message should not verify")
	}
}

func TestMLDSA65Summary(t *testing.T) {
	k, err := pqc.GenerateMLDSA65()
	if err != nil {
		t.Fatalf("GenerateMLDSA65: %v", err)
	}
	s := k.Summary()
	if s["algorithm"] != "ML-DSA-65" {
		t.Errorf("summary algorithm: got %v", s["algorithm"])
	}
}
