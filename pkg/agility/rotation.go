package agility

import "fmt"

// ThreatLevel represents the current assessment of quantum computing risk
// to classical cryptography.
type ThreatLevel int

const (
	// ThreatNone: No credible quantum threat. Classical algorithms are safe.
	ThreatNone ThreatLevel = iota
	// ThreatEmerging: CRQCs (Cryptographically Relevant Quantum Computers)
	// under active development. Begin planning migration.
	ThreatEmerging
	// ThreatImminent: CRQC demonstrated at small scale. Migrate to hybrid
	// algorithms immediately for new key material.
	ThreatImminent
	// ThreatActive: CRQC capable of breaking RSA-2048 / ECDSA P-256.
	// PQC-only — classical algorithms must not be used for new material.
	ThreatActive
)

func (t ThreatLevel) String() string {
	switch t {
	case ThreatNone:
		return "none"
	case ThreatEmerging:
		return "emerging"
	case ThreatImminent:
		return "imminent"
	case ThreatActive:
		return "active"
	default:
		return "unknown"
	}
}

// RotationPolicy maps threat levels to required algorithm sets.
type RotationPolicy struct {
	// SignatureAlgorithm is the required signing algorithm at this threat level.
	SignatureAlgorithm string
	// KEMAlgorithm is the required key exchange algorithm at this threat level.
	KEMAlgorithm string
	// Description explains the rationale.
	Description string
}

// DefaultRotationPolicies returns the recommended algorithm map
// keyed by threat level.
func DefaultRotationPolicies() map[ThreatLevel]RotationPolicy {
	return map[ThreatLevel]RotationPolicy{
		ThreatNone: {
			SignatureAlgorithm: "ES256",
			KEMAlgorithm:       "ECDH-ES",
			Description:        "Classical algorithms sufficient. Begin PQC planning.",
		},
		ThreatEmerging: {
			SignatureAlgorithm: "ES256",
			KEMAlgorithm:       "X25519+ML-KEM-768",
			Description:        "Hybrid KEM to protect long-lived key material. Signature migration in progress.",
		},
		ThreatImminent: {
			SignatureAlgorithm: "ES256+ML-DSA-65",
			KEMAlgorithm:       "X25519+ML-KEM-768",
			Description:        "Full hybrid mode. Both legs required; verify either suffices.",
		},
		ThreatActive: {
			SignatureAlgorithm: "ML-DSA-65",
			KEMAlgorithm:       "ML-KEM-768",
			Description:        "PQC only. Classical algorithms deprecated for new key material.",
		},
	}
}

// PolicyFor returns the rotation policy for the given threat level.
func PolicyFor(level ThreatLevel) (RotationPolicy, error) {
	policies := DefaultRotationPolicies()
	p, ok := policies[level]
	if !ok {
		return RotationPolicy{}, fmt.Errorf("unknown threat level: %d", level)
	}
	return p, nil
}

// RotationNeeded returns true if the current algorithm set must change
// given the new threat level.
func RotationNeeded(currentSig, currentKEM string, newLevel ThreatLevel) bool {
	p, err := PolicyFor(newLevel)
	if err != nil {
		return false
	}
	return currentSig != p.SignatureAlgorithm || currentKEM != p.KEMAlgorithm
}
