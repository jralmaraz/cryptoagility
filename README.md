# Cryptographic Agility

**Live demo:** https://cryptoagility.pages.dev

A PoC exploring post-quantum cryptography (NIST FIPS 203/204/205), cryptographic algorithm agility (RFC 7696), and privacy-preserving AI inference via homomorphic encryption — with a focus on how workload identity and AI agent credentials transition from classical to quantum-safe algorithms.

[![CI](https://github.com/jralmaraz/cryptoagility/actions/workflows/ci.yml/badge.svg)](https://github.com/jralmaraz/cryptoagility/actions/workflows/ci.yml)

## Demo tabs

| Tab | What it shows |
|---|---|
| Overview | Quantum threat timeline, harvest-now-decrypt-later, NIST PQC summary |
| ML-KEM | Live ML-KEM-768 key encapsulation demo (real stdlib implementation) |
| ML-DSA | Digital signature transition — token headers changing from ES256 to ML-DSA-65 |
| Hybrid Classical+PQC | X25519+ML-KEM-768 two-leg handshake (TLS 1.3 hybrid) |
| Crypto Agility | Algorithm negotiation + threat-level rotation policy |
| Private Inference (HE) | Simulated homomorphic encryption for private AI inference |
| Identity Transition | How JWT/WIT/mTLS tokens migrate to post-quantum algorithms |
| Standards | NIST FIPS 203/204/205 + IETF PQUIP/TLS/JOSE tracker |

## Package structure

- `pkg/pqc/` — ML-KEM-768 (NIST FIPS 203, via `crypto/mlkem` stdlib) and ML-DSA-65 (FIPS 204 interface)
- `pkg/agility/` — Algorithm registry, peer negotiation, threat-level rotation policies
- `pkg/inference/` — Simulated additive HE for private AI inference (educational)
- `cmd/demo-wasm/` — WASM entrypoint (7 exported functions)
- `demo/` — Browser demo (`index.html`, `cryptoagility.wasm`, `wasm_exec.js`)

## Build

```bash
# Run tests
go test ./...

# Build WASM
GOOS=js GOARCH=wasm go build -o demo/cryptoagility.wasm ./cmd/demo-wasm/
cp $(go env GOROOT)/lib/wasm/wasm_exec.js demo/
```

## Key standards

| Standard | Purpose |
|---|---|
| [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | ML-KEM — key encapsulation (replaces ECDH) |
| [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | ML-DSA — signatures (replaces ECDSA) |
| [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) | SLH-DSA — stateless hash-based signatures |
| RFC 7696 | Cryptographic Algorithm Agility |
| draft-ietf-pquip-pqc-engineers | PQC engineering guide (IETF PQUIP WG) |

## Scope

This project covers the **cryptographic substrate transition** — how the algorithms underlying identity tokens, key exchange, and AI inference credentials move from classical to quantum-safe. For workload identity protocol details (WIT, WPT, OBO), see [wimse-identity-fabric](https://github.com/example/wimse-identity-fabric) and [ai-agent-security](https://github.com/jralmaraz/ai-agent-security).
