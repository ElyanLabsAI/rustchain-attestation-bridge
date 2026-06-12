// SPDX-License-Identifier: MIT
// Express middleware: gate a route on a valid RustChain attestation token.
//
// This is the recipient side of the engagement demo — "an agent makes an
// x402-paid request, the recipient validates the sender's RustChain attestation
// before accepting." A service drops `requireAttestation(verifier)` in front of
// any route and gets sybil-resistant access control with no call back to the
// bridge: verification is fully offline against the bridge's published pubkey.
//
// Usage:
//   import { createVerifier, requireAttestation } from './verify-middleware.js';
//
//   const verifier = await createVerifier({ bridgeUrl: 'https://bridge.example' });
//   // or: await createVerifier({ publicKeyHex: 'abc123...' })  (no network)
//
//   app.post('/x402/charge',
//     requireAttestation(verifier, { audience: 'x402.example', minTrustScore: 50 }),
//     (req, res) => {
//       // req.attestation holds the verified payload (node_id, device_arch, ...)
//       res.json({ ok: true, charged_by: req.attestation.node_id });
//     });

import { verifyToken, parsePublicKey, policyOptionError } from './attestation.js';

// Errors that mean "valid signature, but caller is not authorized for THIS
// resource" → HTTP 403. Everything else (bad/expired/missing token) → 401.
const POLICY_ERROR = /audience mismatch|trust_score below|device_arch not allowed/;

// Resolve the bridge public key once, up front. Two sources:
//   publicKeyHex — pin the key directly (no network; best for production)
//   bridgeUrl    — fetch it from the bridge's /pubkey endpoint (convenient)
// Returns an opaque verifier handle to pass to requireAttestation().
export async function createVerifier({ publicKeyHex, bridgeUrl, fetchImpl } = {}) {
  if (publicKeyHex) {
    return { publicKey: parsePublicKey(publicKeyHex) };
  }
  if (bridgeUrl) {
    const doFetch = fetchImpl || globalThis.fetch;
    if (typeof doFetch !== 'function') {
      throw new Error('createVerifier: no fetch available — pass fetchImpl or publicKeyHex');
    }
    const url = `${bridgeUrl.replace(/\/+$/, '')}/pubkey`;
    const res = await doFetch(url);
    if (!res.ok) throw new Error(`createVerifier: ${url} returned HTTP ${res.status}`);
    const data = await res.json();
    if (!data?.public_key_hex) {
      throw new Error('createVerifier: bridge /pubkey did not return public_key_hex');
    }
    return { publicKey: parsePublicKey(data.public_key_hex) };
  }
  throw new Error('createVerifier: provide publicKeyHex or bridgeUrl');
}

// Express middleware factory. `verifier` comes from createVerifier().
// Options (all optional):
//   audience        — require the token's aud to equal this (replay binding)
//   minTrustScore   — require trust_score >= this
//   allowDeviceArch — array of acceptable device_arch values
//   header          — header to read the bearer token from (default authorization)
export function requireAttestation(verifier, options = {}) {
  if (!verifier || !(verifier.publicKey instanceof Uint8Array)) {
    throw new Error('requireAttestation: pass a verifier from createVerifier()');
  }
  const { audience, minTrustScore, allowDeviceArch, header = 'authorization' } = options;

  // Fail fast at setup on a misconfigured policy rather than silently letting
  // every request through (fail-open) or failing every request at runtime.
  const perr = policyOptionError({ minTrustScore, allowDeviceArch });
  if (perr) throw new Error(`requireAttestation: ${perr}`);
  const headerName = header.toLowerCase();

  return async function attestationGate(req, res, next) {
    try {
      const token = extractBearer(req, headerName);
      if (!token) {
        return res.status(401).json({
          ok: false,
          error: 'attestation_required',
          hint: `send the attestation token as: ${header}: Bearer <token>`,
        });
      }

      const result = await verifyToken(token, {
        publicKey: verifier.publicKey,
        expectedAudience: audience,
        minTrustScore,
        allowDeviceArch,
      });

      if (!result.valid) {
        const code = POLICY_ERROR.test(result.error || '') ? 403 : 401;
        return res.status(code).json({
          ok: false,
          error: code === 403 ? 'attestation_forbidden' : 'attestation_invalid',
          reason: result.error,
        });
      }

      // Expose verified claims to the route handler.
      req.attestation = result.payload;
      return next();
    } catch {
      // Never leak internals; an unexpected error means we could not verify.
      return res.status(401).json({ ok: false, error: 'attestation_invalid', reason: 'verification_error' });
    }
  };
}

// Pull the bearer token out of a header value: "Bearer <token>".
function extractBearer(req, headerName) {
  const raw = req.headers?.[headerName];
  if (!raw || typeof raw !== 'string') return null;
  const m = raw.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}