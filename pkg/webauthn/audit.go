// Package webauthn provides a COSE algorithm audit for WebAuthn Level 4,
// showing which algorithms are supported and which quantum-safe algorithms
// are missing from the current L4 registry.
package webauthn

// AlgorithmEntry describes a COSE algorithm's WebAuthn support and quantum safety.
type AlgorithmEntry struct {
	COSEAlg     int    // COSE algorithm number (-7 = ES256, -257 = RS256, etc.)
	Name        string // e.g. "ES256"
	Curve       string // e.g. "P-256" (empty for non-EC)
	QuantumSafe bool   // true for ML-DSA-65, ML-KEM-768
	WebAuthnL4  bool   // in the WebAuthn Level 4 COSE registry today
	WebAuthnL5  bool   // hypothetical future status in WebAuthn L5
	Note        string // additional context
}

// Audit returns the COSE algorithm table relevant to WebAuthn passkey deployments.
// Classical algorithms (ES256, RS256, EdDSA) are registered in L4.
// PQC algorithms (ML-DSA-65, ML-KEM-768) have no COSE type assigned yet.
func Audit() []AlgorithmEntry {
	return []AlgorithmEntry{
		{
			COSEAlg:     -7,
			Name:        "ES256",
			Curve:       "P-256",
			QuantumSafe: false,
			WebAuthnL4:  true,
			WebAuthnL5:  true,
			Note:        "Most widely deployed passkey algorithm. Vulnerable to Shor's algorithm.",
		},
		{
			COSEAlg:     -257,
			Name:        "RS256",
			Curve:       "RSA-2048",
			QuantumSafe: false,
			WebAuthnL4:  true,
			WebAuthnL5:  true,
			Note:        "Legacy RSA — large keys, vulnerable to Shor's algorithm.",
		},
		{
			COSEAlg:     -8,
			Name:        "EdDSA",
			Curve:       "Ed25519",
			QuantumSafe: false,
			WebAuthnL4:  true,
			WebAuthnL5:  true,
			Note:        "Efficient and widely supported. Still classically vulnerable.",
		},
		{
			COSEAlg:     0, // TBD — not yet assigned by IANA
			Name:        "ML-DSA-65",
			Curve:       "",
			QuantumSafe: true,
			WebAuthnL4:  false,
			WebAuthnL5:  true,
			Note:        "NIST FIPS 204 — COSE type not yet assigned. Required for PQC passkeys.",
		},
		{
			COSEAlg:     0, // TBD — not yet assigned by IANA
			Name:        "ML-KEM-768",
			Curve:       "",
			QuantumSafe: true,
			WebAuthnL4:  false,
			WebAuthnL5:  false,
			Note:        "NIST FIPS 203 — KEM only, not a signing algorithm. Not applicable to passkeys.",
		},
	}
}

// GapNote returns a human-readable summary of the L4 quantum gap.
func GapNote() string {
	return "WebAuthn L4 supports 3 classical algorithms only (ES256, RS256, EdDSA). " +
		"ML-DSA-65 (NIST FIPS 204) is quantum-safe but has no COSE type assigned yet. " +
		"A future WebAuthn version (L5 or a COSE extension) is required before passkeys can be quantum-safe. " +
		"Until then, all passkey-signed assertions are vulnerable to a sufficiently powerful quantum computer."
}
