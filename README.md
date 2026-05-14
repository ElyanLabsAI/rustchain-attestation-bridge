# RustChain Attestation Bridge

HTTP service that exposes [RustChain](https://github.com/elyanlabs/Rustchain)'s 6-check
hardware-attestation as a callable API. External systems — particularly AI L1 networks
like ChainGPT AIVM and any DePIN platform that needs VM-resistant compute — submit
hardware fingerprint data and receive Ed25519-signed attestation tokens proving the
submitting hardware is real silicon, not an emulator or hypervisor.

Built by [Elyan Labs](https://elyanlabs.ai) as a reference integration for any
ecosystem that wants to gate rewards/access by hardware authenticity without
re-implementing the attestation stack.

---

## Why this exists

DePIN networks reward compute. AI L1s reward inference. Both need to know whether
the participating node is **real hardware** or a VM farm gaming rewards. RustChain
solved this with 6 hardware fingerprint checks that work on real silicon and fail
on emulation:

1. **Clock-Skew & Oscillator Drift** — real silicon has measurable timing variance
2. **Cache Timing Fingerprint** — L1/L2/L3 latency profile
3. **SIMD Unit Identity** — pipeline depth + bias profile
4. **Thermal Drift Entropy** — physical heat curves
5. **Instruction Path Jitter** — cycle-level jitter signatures
6. **Anti-Emulation Behavioral** — hypervisor / VM detection

Most DePIN/AI projects don't want to re-implement all six. The bridge makes them
callable as a service.

---

## Architecture

```
┌──────────────────────┐       ┌──────────────────────────────┐
│  External System     │       │  RustChain Attestation       │
│  (ChainGPT AIVM,     │       │  Bridge (this service)       │
│   DePIN, anything)   │       │                              │
│                      │  POST │  - validates fingerprint     │
│  1. Run 6 checks     │──────▶│  - rejects VM submissions    │
│     locally          │       │  - issues Ed25519 token      │
│                      │  ◀────│                              │
│  2. Receive token    │       │                              │
│                      │       │  Public key published at     │
│  3. Embed in TXs /   │       │  /pubkey for offline verify  │
│     API calls        │       └──────────────────────────────┘
│                      │
│  4. Anyone verifies  │
│     offline against  │
│     bridge pubkey    │
└──────────────────────┘
```

The bridge is **stateless after issuance**. Tokens carry their claims; verification
happens against the bridge's published public key. No database lookup needed for
verification, which scales to any node count.

---

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/attest` | Submit fingerprint, receive Ed25519-signed attestation token |
| `GET` | `/verify/:token` | Server-side token verification (convenience; offline verification is preferred) |
| `GET` | `/pubkey` | Bridge public key for offline verification |
| `GET` | `/health` | Health check |

---

## Token format

```
base64url(payload).base64url(signature)
```

Payload (JSON):

```json
{
  "v": 1,
  "node_id": "<stable id from fingerprint>",
  "hardware_class": "real_hardware",
  "device_arch": "g4 | g5 | power8 | modern | apple_silicon | ...",
  "trust_score": 100,
  "attested_at": 1778768931,
  "expires_at": 1778855331,
  "bridge_url": "https://attest.elyanlabs.io"
}
```

Signature: Ed25519 over the payload bytes, verifiable with the bridge public key.

---

## Quick start

```bash
git clone https://github.com/elyanlabs/rustchain-attestation-bridge.git
cd rustchain-attestation-bridge
npm install

# Generate bridge keypair (one-time)
npm run keygen
# Copy the BRIDGE_PRIVATE_KEY and BRIDGE_PUBLIC_KEY into .env

# Start the bridge
npm start
```

Then submit a fingerprint:

```bash
curl -X POST http://localhost:3001/attest \
  -H "Content-Type: application/json" \
  -d '{
    "hardware_id": "my-node-1234567890abcdef",
    "device": {"device_family": "x86_64", "device_arch": "modern"},
    "checks": {
      "anti_emulation": {"passed": true},
      "clock_drift": {"passed": true, "data": {"cv": 0.08}},
      "cache_timing": {"passed": true},
      "simd_identity": {"passed": true},
      "thermal_drift": {"passed": true},
      "instruction_jitter": {"passed": true}
    }
  }'
```

Response:

```json
{
  "ok": true,
  "token": "eyJ2IjoxLCJub2RlX2lkIjoi...",
  "payload": { "...verified claims..." },
  "validation": { "score": 100, "warnings": [] }
}
```

---

## Integration: ChainGPT AIVM (or any L1 / DePIN node)

```javascript
import * as ed from '@noble/ed25519';

// 1. Run RustChain's 6 fingerprint checks locally
//    (using the published fingerprint_checks.py or a port to your language)
const fingerprint = await runHardwareFingerprintChecks();

// 2. Submit to bridge
const res = await fetch('https://attest.elyanlabs.io/attest', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(fingerprint),
});
const { ok, token, payload } = await res.json();

if (!ok) {
  throw new Error('Hardware attestation failed — likely VM detected');
}

// 3. Embed token in subsequent calls
//    e.g., Authorization: Bearer <token> when claiming inference rewards
//    e.g., transaction metadata field for on-chain proof of attested compute

// 4. Verify offline (anyone can do this with the bridge public key)
const bridgePubKey = '<hex string from /pubkey, cached>';
const valid = await verifyTokenOffline(token, bridgePubKey);
```

See [`examples/client-aivm.js`](examples/client-aivm.js) for a complete worked example.

---

## What this validates server-side

The bridge does NOT re-run the 6 checks (those must run on the actual hardware to
produce real measurements). Instead, the bridge validates that the submitted
RESULTS are well-formed and don't show telltale signs of forgery:

- **anti_emulation must be present and pass** — the only hard gate
- **clock_drift CV must exceed 0.0001** — real silicon has measurable variance;
  synthetic clocks are too uniform
- **ROM hash check (if applicable)** — vintage hardware ROM cluster detection
  catches emulator farms running identical Mac/Amiga ROMs
- **Optional 4 checks** — failures emit warnings, lower trust score, but don't
  block issuance unless anti_emulation also fails

Trust score = `(passed_checks / 6) * 100`. A node that submits all 6 passing
gets 100; a node that submits only the 2 required gets ~33.

---

## Security model

- **Bridge private key** lives in `.env` (mode 600), never committed
- **Bridge public key** is published at `/pubkey` and should be cached by verifiers
- **Tokens are short-lived** (24h default) — long-running services re-attest periodically
- **Tokens are stateless** — no server-side session, all claims embedded
- **Forgery requires the bridge's private key** — protect it

---

## Run tests

```bash
npm test
```

Tests cover: validateFingerprint accept/reject paths, attestation issue+verify
roundtrip, tampered token rejection, expired token rejection, deriveNodeId
stability.

---

## Status

**v0.0.1 PoC — May 14, 2026.** Not yet production-deployed. Intended as a
reference implementation that DePIN networks can fork, adapt, or call directly.

---

## License

MIT — Elyan Labs

---

## Related

- [RustChain](https://github.com/elyanlabs/Rustchain) — the source-of-truth chain whose attestation scheme this exposes
- [ChainGPT AIVM](https://docs.chaingpt.org/overview/road-map/2024-2025-aivm-blockchain-initiative) — example consumer (AI L1 that needs VM-resistant nodes)
- `fingerprint_checks.py` — the original 6-check implementation (in the RustChain repo)
