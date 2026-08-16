//go:build js && wasm

// Package main compiles to WebAssembly and exposes cryptographic agility
// demonstration functions to the browser demo.
package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/jralmaraz/cryptoagility/pkg/agility"
	"github.com/jralmaraz/cryptoagility/pkg/inference"
	"github.com/jralmaraz/cryptoagility/pkg/pqc"
)

func main() {
	js.Global().Set("cryptoAgilityInit", js.FuncOf(cryptoAgilityInit))
	js.Global().Set("mlkemDemo", js.FuncOf(mlkemDemo))
	js.Global().Set("mldsaDemo", js.FuncOf(mldsaDemo))
	js.Global().Set("hybridKEMDemo", js.FuncOf(hybridKEMDemo))
	js.Global().Set("agilityNegotiateDemo", js.FuncOf(agilityNegotiateDemo))
	js.Global().Set("keyRotationDemo", js.FuncOf(keyRotationDemo))
	js.Global().Set("heInferenceDemo", js.FuncOf(heInferenceDemo))

	js.Global().Get("document").Call("dispatchEvent",
		js.Global().Get("CustomEvent").New("wasm-ready",
			map[string]interface{}{"detail": "cryptoagility"}))

	select {}
}

func cryptoAgilityInit(_ js.Value, _ []js.Value) interface{} {
	return map[string]interface{}{
		"ok":      true,
		"version": "NIST FIPS 203/204/205 (2024)",
		"module":  "cryptoagility",
		"algorithms": []interface{}{
			"ML-KEM-768 (FIPS 203)", "ML-DSA-65 (FIPS 204)",
			"SLH-DSA-128s (FIPS 205)", "X25519+ML-KEM-768 (hybrid)",
			"ES256+ML-DSA-65 (hybrid)",
		},
	}
}

// mlkemDemo generates an ML-KEM-768 key pair, encapsulates, and decapsulates.
func mlkemDemo(_ js.Value, _ []js.Value) interface{} {
	k, err := pqc.GenerateMLKEM768()
	if err != nil {
		return errResult(err.Error())
	}
	ek := k.EncapsulationKey()

	ct, ss1, err := pqc.Encapsulate(ek)
	if err != nil {
		return errResult(err.Error())
	}
	ss2, err := k.Decapsulate(ct)
	if err != nil {
		return errResult(err.Error())
	}
	match := len(ss1) == len(ss2)
	if match {
		for i := range ss1 {
			if ss1[i] != ss2[i] {
				match = false
				break
			}
		}
	}

	summary := k.Summary()
	return map[string]interface{}{
		"ok":      true,
		"summary": summary,
		"steps": []interface{}{
			map[string]interface{}{
				"label": "1. Key Generation (recipient)",
				"detail": fmt.Sprintf(
					"Generated ML-KEM-768 decapsulation key (%d bytes private, %d bytes public encapsulation key)",
					pqc.MLKEM768DecapKeyBytes, pqc.MLKEM768EncapKeyBytes),
			},
			map[string]interface{}{
				"label": "2. Encapsulate (sender)",
				"detail": fmt.Sprintf(
					"Encapsulated shared secret: produced %d-byte ciphertext + 32-byte shared secret",
					len(ct)),
			},
			map[string]interface{}{
				"label": "3. Decapsulate (recipient)",
				"detail": fmt.Sprintf(
					"Decapsulated ciphertext → 32-byte shared secret. Secrets match: %v", match),
			},
		},
		"classical_comparison": map[string]interface{}{
			"ECDH_P256_pub_bytes":    65,
			"ML_KEM_768_pub_bytes":   pqc.MLKEM768EncapKeyBytes,
			"ECDH_P256_ct_bytes":     65,
			"ML_KEM_768_ct_bytes":    pqc.MLKEM768CiphertextBytes,
			"ECDH_P256_quantum_safe": false,
			"ML_KEM_768_quantum_safe": true,
		},
	}
}

// mldsaDemo generates an ML-DSA-65 key pair and shows sign/verify.
func mldsaDemo(_ js.Value, _ []js.Value) interface{} {
	k, err := pqc.GenerateMLDSA65()
	if err != nil {
		return errResult(err.Error())
	}
	msg := []byte(`{"typ":"agent+jwt","alg":"ML-DSA-65","sub":"spiffe://bank.internal/payments-agent"}`)
	sig, err := k.Sign(msg)
	if err != nil {
		return errResult(err.Error())
	}
	valid := k.Verify(msg, sig)

	summary := k.Summary()
	return map[string]interface{}{
		"ok":      true,
		"summary": summary,
		"jwt_header": map[string]interface{}{
			"typ": "agent+jwt",
			"alg": "ML-DSA-65",
		},
		"sign_verify": map[string]interface{}{
			"message_bytes": len(msg),
			"sig_bytes":     len(sig),
			"valid":         valid,
		},
		"classical_comparison": map[string]interface{}{
			"EdDSA_pub_bytes":        32,
			"ML_DSA_65_pub_bytes":    pqc.MLDSA65PublicKeyBytes,
			"EdDSA_sig_bytes":        64,
			"ML_DSA_65_sig_bytes":    pqc.MLDSA65SignatureBytes,
			"EdDSA_quantum_safe":     false,
			"ML_DSA_65_quantum_safe": true,
		},
	}
}

// hybridKEMDemo shows X25519+ML-KEM-768 side-by-side.
func hybridKEMDemo(_ js.Value, _ []js.Value) interface{} {
	k, err := pqc.GenerateMLKEM768()
	if err != nil {
		return errResult(err.Error())
	}
	ek := k.EncapsulationKey()
	ct, _, err := pqc.Encapsulate(ek)
	if err != nil {
		return errResult(err.Error())
	}
	return map[string]interface{}{
		"ok": true,
		"explanation": "Hybrid KEM (X25519+ML-KEM-768) runs two key exchanges in parallel. " +
			"The final shared secret = KDF(X25519_ss || ML-KEM_ss). " +
			"Breaking it requires breaking BOTH algorithms — defense-in-depth during transition.",
		"legs": []interface{}{
			map[string]interface{}{
				"name":        "Leg 1: X25519 (classical)",
				"pub_bytes":   32,
				"ct_bytes":    32,
				"ss_bytes":    32,
				"quantum_safe": false,
				"breaks_if":   "CRQC built (Shor's algorithm)",
			},
			map[string]interface{}{
				"name":        "Leg 2: ML-KEM-768 (post-quantum)",
				"pub_bytes":   len(ek),
				"ct_bytes":    len(ct),
				"ss_bytes":    32,
				"quantum_safe": true,
				"breaks_if":   "ML-KEM broken by classical attack (no known attack)",
			},
		},
		"combined": map[string]interface{}{
			"total_pub_bytes": 32 + len(ek),
			"total_ct_bytes":  32 + len(ct),
			"final_ss_bytes":  32,
			"quantum_safe":    true,
		},
		"tls_context": "Used as X25519MLKEM768 key share in TLS 1.3 ClientHello (RFC 9258 hybrid groups)",
	}
}

// agilityNegotiateDemo shows algorithm negotiation between two peers.
// args[0]: JSON array of local algorithm IDs
// args[1]: JSON array of remote algorithm IDs
func agilityNegotiateDemo(_ js.Value, args []js.Value) interface{} {
	local := []string{"ES256", "ML-DSA-65", "X25519+ML-KEM-768"}
	remote := []string{"ES256", "EdDSA", "ML-DSA-65"}

	if len(args) > 0 {
		if err := json.Unmarshal([]byte(args[0].String()), &local); err != nil {
			return errResult("invalid local JSON: " + err.Error())
		}
	}
	if len(args) > 1 {
		if err := json.Unmarshal([]byte(args[1].String()), &remote); err != nil {
			return errResult("invalid remote JSON: " + err.Error())
		}
	}

	reg := agility.DefaultRegistry()
	nr := agility.NegotiateWithReason(local, remote, reg)

	if nr.Selected == nil {
		return map[string]interface{}{
			"ok":             false,
			"error":          nr.Reason,
			"local_offered":  toIfaceSlice(local),
			"remote_offered": toIfaceSlice(remote),
		}
	}
	return map[string]interface{}{
		"ok":             true,
		"selected":       nr.Selected.ID,
		"type":           nr.Selected.Type.String(),
		"quantum_safe":   nr.Selected.QuantumSafe,
		"reason":         nr.Reason,
		"local_offered":  toIfaceSlice(local),
		"remote_offered": toIfaceSlice(remote),
	}
}

// keyRotationDemo shows the rotation policy for a given threat level.
// args[0]: threat level string ("none", "emerging", "imminent", "active")
func keyRotationDemo(_ js.Value, args []js.Value) interface{} {
	levelStr := "none"
	if len(args) > 0 {
		levelStr = args[0].String()
	}

	levelMap := map[string]agility.ThreatLevel{
		"none":     agility.ThreatNone,
		"emerging": agility.ThreatEmerging,
		"imminent": agility.ThreatImminent,
		"active":   agility.ThreatActive,
	}
	level, ok := levelMap[levelStr]
	if !ok {
		return errResult("unknown threat level: " + levelStr)
	}

	p, err := agility.PolicyFor(level)
	if err != nil {
		return errResult(err.Error())
	}

	// Show all levels for the table view.
	all := make([]interface{}, 0, 4)
	for _, l := range []agility.ThreatLevel{
		agility.ThreatNone, agility.ThreatEmerging,
		agility.ThreatImminent, agility.ThreatActive,
	} {
		lp, _ := agility.PolicyFor(l)
		all = append(all, map[string]interface{}{
			"level":     l.String(),
			"sig_alg":   lp.SignatureAlgorithm,
			"kem_alg":   lp.KEMAlgorithm,
			"active":    l == level,
			"description": lp.Description,
		})
	}

	needsRotation := agility.RotationNeeded("ES256", "ECDH-ES", level)
	return map[string]interface{}{
		"ok":             true,
		"current_level":  levelStr,
		"policy":         map[string]interface{}{
			"sig_alg":     p.SignatureAlgorithm,
			"kem_alg":     p.KEMAlgorithm,
			"description": p.Description,
		},
		"rotation_needed": needsRotation,
		"all_levels":      all,
	}
}

// heInferenceDemo simulates private AI inference using homomorphic encryption.
// args[0]: JSON object with "inputs" ([]int) and "weights" ([]float64)
func heInferenceDemo(_ js.Value, args []js.Value) interface{} {
	type req struct {
		Inputs  []int64   `json:"inputs"`
		Weights []float64 `json:"weights"`
	}
	r := req{
		Inputs:  []int64{5, 3, 8},
		Weights: []float64{0.4, 0.9, 0.3},
	}
	if len(args) > 0 {
		if err := json.Unmarshal([]byte(args[0].String()), &r); err != nil {
			return errResult("invalid JSON: " + err.Error())
		}
	}
	if len(r.Inputs) == 0 || len(r.Inputs) != len(r.Weights) {
		return errResult("inputs and weights must be non-empty and equal length")
	}

	key := inference.GenerateHEKey()

	// Client encrypts inputs.
	encInputs := make([]*inference.EncryptedInt, len(r.Inputs))
	clientView := make([]interface{}, len(r.Inputs))
	for i, v := range r.Inputs {
		encInputs[i] = key.Encrypt(v)
		clientView[i] = map[string]interface{}{
			"plaintext":  v,
			"ciphertext": encInputs[i].Ciphertext(),
		}
	}

	// Server runs inference on ciphertexts (never sees plaintext).
	result, err := inference.RunInference(encInputs, r.Weights)
	if err != nil {
		return errResult(err.Error())
	}

	// Client decrypts result.
	decrypted := inference.DecryptResult(result, key)

	stepList := make([]interface{}, len(result.Steps))
	for i, s := range result.Steps {
		stepList[i] = s
	}

	return map[string]interface{}{
		"ok":         true,
		"key_id":     key.ID(),
		"client_encrypted_inputs": clientView,
		"server_computation": map[string]interface{}{
			"sees_only":   "encrypted ciphertexts (not plaintext inputs)",
			"weights":     floatSlice(r.Weights),
			"steps":       stepList,
			"enc_output_ciphertext": result.EncryptedOutput.Ciphertext(),
		},
		"client_decrypted_output": decrypted,
		"explanation": fmt.Sprintf(
			"Server computed weighted sum on encrypted inputs. "+
				"Client decrypted: %.3f (= Σ input×weight, scaled ÷ 1000)",
			decrypted),
	}
}

// --- helpers ---

func errResult(msg string) map[string]interface{} {
	return map[string]interface{}{"ok": false, "error": msg}
}

func toIfaceSlice(ss []string) []interface{} {
	out := make([]interface{}, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func floatSlice(fs []float64) []interface{} {
	out := make([]interface{}, len(fs))
	for i, f := range fs {
		out[i] = f
	}
	return out
}
