// Package agility implements cryptographic algorithm negotiation, rotation
// policies, and the algorithm registry for the crypto-agility PoC.
//
// Crypto agility (RFC 7696) is the ability of a system to negotiate and
// switch cryptographic algorithms without changing the overall protocol
// structure. This is critical during the classical → post-quantum transition.
package agility

import "fmt"

// AlgorithmType categorises an algorithm by its quantum-safety posture.
type AlgorithmType int

const (
	Classical    AlgorithmType = iota // ECDSA, ECDH — broken by CRQC
	Hybrid                            // Classical + PQC in parallel (transition)
	PostQuantum                       // ML-KEM, ML-DSA — quantum-safe
)

func (t AlgorithmType) String() string {
	switch t {
	case Classical:
		return "classical"
	case Hybrid:
		return "hybrid"
	case PostQuantum:
		return "post-quantum"
	default:
		return "unknown"
	}
}

// AlgorithmStatus reflects whether an algorithm is actively recommended.
type AlgorithmStatus int

const (
	Recommended  AlgorithmStatus = iota // Use today
	Transitional                        // Acceptable during migration window
	Deprecated                          // Do not use for new key material
)

func (s AlgorithmStatus) String() string {
	switch s {
	case Recommended:
		return "recommended"
	case Transitional:
		return "transitional"
	case Deprecated:
		return "deprecated"
	default:
		return "unknown"
	}
}

// Algorithm describes a single cryptographic algorithm and its properties.
type Algorithm struct {
	ID             string
	Name           string
	Type           AlgorithmType
	KeyExchange    bool // supports key exchange / encapsulation
	Signature      bool // supports digital signatures
	QuantumSafe    bool
	SecurityLevel  int    // classical security bits
	NISTFIPS       string // e.g., "FIPS 203"
	JOSEAlg        string // JOSE "alg" header value (if standardised)
	Status         AlgorithmStatus
	PublicKeyBytes int // 0 = not applicable
	SigBytes       int // 0 = not applicable
	CTBytes        int // ciphertext / KEM bytes; 0 = not applicable
}

// Registry holds the set of known algorithms indexed by ID.
type Registry struct {
	algorithms map[string]*Algorithm
}

// DefaultRegistry returns a registry pre-populated with classical,
// hybrid, and post-quantum algorithms relevant to the identity transition.
func DefaultRegistry() *Registry {
	r := &Registry{algorithms: make(map[string]*Algorithm)}
	r.register(
		// Classical
		&Algorithm{
			ID: "ES256", Name: "ECDSA P-256", Type: Classical,
			Signature: true, QuantumSafe: false, SecurityLevel: 128,
			JOSEAlg: "ES256", Status: Transitional,
			PublicKeyBytes: 65, SigBytes: 72,
		},
		&Algorithm{
			ID: "EdDSA", Name: "Ed25519", Type: Classical,
			Signature: true, QuantumSafe: false, SecurityLevel: 128,
			JOSEAlg: "EdDSA", Status: Transitional,
			PublicKeyBytes: 32, SigBytes: 64,
		},
		&Algorithm{
			ID: "ECDH-ES", Name: "ECDH P-256", Type: Classical,
			KeyExchange: true, QuantumSafe: false, SecurityLevel: 128,
			Status: Transitional, PublicKeyBytes: 65, CTBytes: 65,
		},
		// Post-quantum
		&Algorithm{
			ID: "ML-KEM-768", Name: "ML-KEM-768", Type: PostQuantum,
			KeyExchange: true, QuantumSafe: true, SecurityLevel: 192,
			NISTFIPS: "FIPS 203", Status: Recommended,
			PublicKeyBytes: 1184, CTBytes: 1088,
		},
		&Algorithm{
			ID: "ML-KEM-1024", Name: "ML-KEM-1024", Type: PostQuantum,
			KeyExchange: true, QuantumSafe: true, SecurityLevel: 256,
			NISTFIPS: "FIPS 203", Status: Recommended,
			PublicKeyBytes: 1568, CTBytes: 1568,
		},
		&Algorithm{
			ID: "ML-DSA-65", Name: "ML-DSA-65", Type: PostQuantum,
			Signature: true, QuantumSafe: true, SecurityLevel: 192,
			NISTFIPS: "FIPS 204", Status: Recommended,
			PublicKeyBytes: 1952, SigBytes: 3309,
		},
		&Algorithm{
			ID: "ML-DSA-87", Name: "ML-DSA-87", Type: PostQuantum,
			Signature: true, QuantumSafe: true, SecurityLevel: 256,
			NISTFIPS: "FIPS 204", Status: Recommended,
			PublicKeyBytes: 2592, SigBytes: 4595,
		},
		&Algorithm{
			ID: "SLH-DSA-128s", Name: "SLH-DSA-128s (SPHINCS+)", Type: PostQuantum,
			Signature: true, QuantumSafe: true, SecurityLevel: 128,
			NISTFIPS: "FIPS 205", Status: Recommended,
			PublicKeyBytes: 32, SigBytes: 7856,
		},
		// Hybrid
		&Algorithm{
			ID: "X25519+ML-KEM-768", Name: "X25519+ML-KEM-768 (TLS hybrid)", Type: Hybrid,
			KeyExchange: true, QuantumSafe: true, SecurityLevel: 128,
			Status: Recommended,
			PublicKeyBytes: 32 + 1184, CTBytes: 32 + 1088,
		},
		&Algorithm{
			ID: "ES256+ML-DSA-65", Name: "ECDSA P-256 + ML-DSA-65 (hybrid sig)", Type: Hybrid,
			Signature: true, QuantumSafe: true, SecurityLevel: 128,
			Status: Recommended,
			SigBytes: 72 + 3309,
		},
	)
	return r
}

func (r *Registry) register(algs ...*Algorithm) {
	for _, a := range algs {
		r.algorithms[a.ID] = a
	}
}

// Get returns the algorithm by ID, or an error if not found.
func (r *Registry) Get(id string) (*Algorithm, error) {
	a, ok := r.algorithms[id]
	if !ok {
		return nil, fmt.Errorf("unknown algorithm: %q", id)
	}
	return a, nil
}

// All returns all registered algorithms.
func (r *Registry) All() []*Algorithm {
	out := make([]*Algorithm, 0, len(r.algorithms))
	for _, a := range r.algorithms {
		out = append(out, a)
	}
	return out
}

// Filter returns algorithms matching the given predicate.
func (r *Registry) Filter(fn func(*Algorithm) bool) []*Algorithm {
	var out []*Algorithm
	for _, a := range r.algorithms {
		if fn(a) {
			out = append(out, a)
		}
	}
	return out
}
