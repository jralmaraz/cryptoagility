package webauthn_test

import (
	"testing"

	"github.com/jralmaraz/cryptoagility/pkg/webauthn"
)

func TestAuditReturnsAllAlgorithms(t *testing.T) {
	entries := webauthn.Audit()
	if len(entries) < 5 {
		t.Errorf("Audit() returned %d entries, want >= 5", len(entries))
	}
}

func TestAuditMLDSANotInL4(t *testing.T) {
	for _, e := range webauthn.Audit() {
		if e.Name == "ML-DSA-65" && e.WebAuthnL4 {
			t.Error("ML-DSA-65 should NOT be in WebAuthn L4 — no COSE type assigned yet")
		}
	}
	// Also verify it appears in the table at all
	found := false
	for _, e := range webauthn.Audit() {
		if e.Name == "ML-DSA-65" {
			found = true
			if !e.QuantumSafe {
				t.Error("ML-DSA-65 must be marked quantum-safe")
			}
			if !e.WebAuthnL5 {
				t.Error("ML-DSA-65 should be projected for WebAuthn L5")
			}
		}
	}
	if !found {
		t.Error("ML-DSA-65 not found in Audit() output")
	}
}

func TestAuditES256IsClassical(t *testing.T) {
	found := false
	for _, e := range webauthn.Audit() {
		if e.Name == "ES256" {
			found = true
			if e.QuantumSafe {
				t.Error("ES256 must NOT be marked quantum-safe")
			}
			if !e.WebAuthnL4 {
				t.Error("ES256 must be in WebAuthn L4")
			}
			if e.COSEAlg != -7 {
				t.Errorf("ES256 COSE alg: got %d, want -7", e.COSEAlg)
			}
		}
	}
	if !found {
		t.Error("ES256 not found in Audit() output")
	}
}

func TestAuditGapNoteNotEmpty(t *testing.T) {
	note := webauthn.GapNote()
	if note == "" {
		t.Error("GapNote() returned empty string")
	}
}

func TestAuditClassicalCount(t *testing.T) {
	var classical int
	for _, e := range webauthn.Audit() {
		if e.WebAuthnL4 {
			classical++
		}
	}
	if classical != 3 {
		t.Errorf("expected 3 L4 algorithms, got %d", classical)
	}
}
