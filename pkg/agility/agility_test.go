package agility_test

import (
	"testing"

	"github.com/jralmaraz/cryptoagility/pkg/agility"
)

var reg = agility.DefaultRegistry()

// --- Registry tests ---

func TestRegistryGet(t *testing.T) {
	ids := []string{"ES256", "ML-KEM-768", "ML-DSA-65", "X25519+ML-KEM-768", "ES256+ML-DSA-65"}
	for _, id := range ids {
		a, err := reg.Get(id)
		if err != nil {
			t.Errorf("Get(%q): %v", id, err)
			continue
		}
		if a.ID != id {
			t.Errorf("Get(%q).ID = %q", id, a.ID)
		}
	}
}

func TestRegistryUnknown(t *testing.T) {
	_, err := reg.Get("RSA-2048")
	if err == nil {
		t.Error("expected error for unknown algorithm")
	}
}

func TestRegistryFilter(t *testing.T) {
	pq := reg.Filter(func(a *agility.Algorithm) bool { return a.Type == agility.PostQuantum })
	if len(pq) == 0 {
		t.Error("no post-quantum algorithms in registry")
	}
	for _, a := range pq {
		if !a.QuantumSafe {
			t.Errorf("%s: Type=PostQuantum but QuantumSafe=false", a.ID)
		}
	}
}

// --- Negotiation tests ---

func TestNegotiatePostQuantumWins(t *testing.T) {
	local := []string{"ES256", "ML-DSA-65", "X25519+ML-KEM-768"}
	remote := []string{"ML-DSA-65", "ES256"}
	a, err := agility.Negotiate(local, remote, reg)
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	if a.Type != agility.PostQuantum {
		t.Errorf("expected PostQuantum winner, got %s (%s)", a.ID, a.Type)
	}
}

func TestNegotiateHybridOverClassical(t *testing.T) {
	local := []string{"ES256", "X25519+ML-KEM-768"}
	remote := []string{"ES256", "X25519+ML-KEM-768"}
	a, err := agility.Negotiate(local, remote, reg)
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	if a.Type != agility.Hybrid {
		t.Errorf("expected Hybrid winner, got %s (%s)", a.ID, a.Type)
	}
}

func TestNegotiateNoCommon(t *testing.T) {
	_, err := agility.Negotiate([]string{"ML-DSA-65"}, []string{"ES256"}, reg)
	if err == nil {
		t.Error("expected error when no common algorithm")
	}
}

func TestNegotiateEmpty(t *testing.T) {
	_, err := agility.Negotiate([]string{}, []string{"ES256"}, reg)
	if err == nil {
		t.Error("expected error for empty local list")
	}
}

// --- Rotation tests ---

func TestRotationPolicyCoverage(t *testing.T) {
	levels := []agility.ThreatLevel{
		agility.ThreatNone,
		agility.ThreatEmerging,
		agility.ThreatImminent,
		agility.ThreatActive,
	}
	for _, l := range levels {
		p, err := agility.PolicyFor(l)
		if err != nil {
			t.Errorf("PolicyFor(%s): %v", l, err)
			continue
		}
		if p.SignatureAlgorithm == "" || p.KEMAlgorithm == "" {
			t.Errorf("PolicyFor(%s): incomplete policy", l)
		}
	}
}

func TestRotationNeeded(t *testing.T) {
	// Classical sig + classical KEM at ThreatActive → rotation needed
	if !agility.RotationNeeded("ES256", "ECDH-ES", agility.ThreatActive) {
		t.Error("expected rotation needed for ThreatActive with classical algorithms")
	}
	// PQC sig + PQC KEM at ThreatActive → no rotation
	if agility.RotationNeeded("ML-DSA-65", "ML-KEM-768", agility.ThreatActive) {
		t.Error("no rotation expected when already using PQC algorithms")
	}
}

func TestThreatLevelString(t *testing.T) {
	cases := map[agility.ThreatLevel]string{
		agility.ThreatNone:     "none",
		agility.ThreatEmerging: "emerging",
		agility.ThreatImminent: "imminent",
		agility.ThreatActive:   "active",
	}
	for level, want := range cases {
		if got := level.String(); got != want {
			t.Errorf("ThreatLevel(%d).String() = %q, want %q", level, got, want)
		}
	}
}
