// SPDX-License-Identifier: MIT
// Attestation token issuance + verification using Ed25519.
//
// Token format (compact, URL-safe):
//   base64url(payloadJson) + "." + base64url(signature)
//
// Payload contains the verified claims; signature proves they were issued by
// the bridge holding a specific private key. Anyone with the public key can
// verify offline.

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512.js';

// @noble/ed25519 v2 requires a sync sha512 for some operations
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const ATTESTATION_TTL_SECONDS = 24 * 60 * 60; // 24h

export class Attestation {
  constructor({ privateKey, bridgeUrl }) {
    if (!privateKey || !(privateKey instanceof Uint8Array) || privateKey.length !== 32) {
      throw new Error('Attestation: privateKey must be a 32-byte Uint8Array');
    }
    this._privateKey = privateKey;
    this._publicKey = null;
    this._bridgeUrl = bridgeUrl || 'http://localhost:3000';
  }

  async getPublicKey() {
    if (!this._publicKey) {
      this._publicKey = await ed.getPublicKey(this._privateKey);
    }
    return this._publicKey;
  }

  async getPublicKeyHex() {
    const pk = await this.getPublicKey();
    return Buffer.from(pk).toString('hex');
  }

  // Issue an attestation token for a verified fingerprint submission.
  //
  // `audience` (optional) binds the token to a specific recipient/service. A
  // recipient that checks the audience will reject a token minted for a
  // different recipient — replay/sybil resistance for x402-style flows where a
  // captured bearer token could otherwise be reused against any service.
  async issue({ nodeId, hardwareClass, deviceArch, trustScore, audience, ttlSeconds = ATTESTATION_TTL_SECONDS }) {
    if (!nodeId) throw new Error('Attestation.issue: nodeId required');

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      v: 1,
      node_id: nodeId,
      hardware_class: hardwareClass || 'unknown',
      device_arch: deviceArch || 'unknown',
      trust_score: trustScore ?? 0,
      attested_at: now,
      expires_at: now + ttlSeconds,
      bridge_url: this._bridgeUrl,
    };

    if (audience !== undefined && audience !== null) {
      // Reject (do NOT silently truncate): a token bound to a truncated audience
      // would differ from what the caller requested. The HTTP layer enforces the
      // same 200-char cap, so library and HTTP callers behave identically.
      if (typeof audience !== 'string' || audience.length === 0 || audience.length > 200) {
        throw new Error('Attestation.issue: audience must be a non-empty string ≤200 chars when provided');
      }
      payload.aud = audience;
    }

    const payloadJson = JSON.stringify(payload);
    const payloadBytes = new TextEncoder().encode(payloadJson);
    const signature = await ed.sign(payloadBytes, this._privateKey);

    return {
      token: `${b64url(payloadBytes)}.${b64url(signature)}`,
      payload,
    };
  }

  // Verify a token using this bridge's own keypair. Delegates to the standalone
  // verifyToken() (which needs only a public key) so the crypto/policy logic
  // lives in exactly one place. Accepts the same policy options.
  async verify(token, { publicKey = null, expectedAudience, minTrustScore, allowDeviceArch, now } = {}) {
    const pk = publicKey || (await this.getPublicKey());
    return verifyToken(token, { publicKey: pk, expectedAudience, minTrustScore, allowDeviceArch, now });
  }
}

// Validate recipient policy options. Returns an error STRING if a provided
// option is malformed, else null. A malformed policy must never silently
// disable enforcement — an auth gate fails closed on misconfiguration.
export function policyOptionError({ minTrustScore, allowDeviceArch } = {}) {
  if (minTrustScore !== undefined && minTrustScore !== null && !Number.isFinite(minTrustScore)) {
    return 'minTrustScore must be a finite number';
  }
  if (allowDeviceArch !== undefined && allowDeviceArch !== null) {
    if (!Array.isArray(allowDeviceArch) || allowDeviceArch.length === 0 || !allowDeviceArch.every((s) => typeof s === 'string')) {
      return 'allowDeviceArch must be a non-empty array of strings';
    }
  }
  return null;
}

// Normalize a public key from a 64-char hex string or a 32-byte Uint8Array.
// Throws on anything else — a verifier with no/garbage key must fail loudly.
export function parsePublicKey(publicKey) {
  if (publicKey instanceof Uint8Array) {
    if (publicKey.length !== 32) throw new Error('publicKey must be 32 bytes');
    return publicKey;
  }
  if (typeof publicKey === 'string') {
    const hex = publicKey.trim();
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error('publicKey hex must be 64 hex chars');
    return Uint8Array.from(Buffer.from(hex, 'hex'));
  }
  throw new Error('publicKey is required (64-char hex string or 32-byte Uint8Array)');
}

// Standalone, offline token verification — needs ONLY the bridge's public key.
// This is the path a recipient service uses: no private key, no call back to the
// bridge. Returns { valid, payload, error }.
//
// Policy options (all optional, opt-in):
//   expectedAudience  — require payload.aud === this value (replay binding)
//   minTrustScore     — require payload.trust_score >= this value
//   allowDeviceArch   — array; require payload.device_arch ∈ this list
//   now               — override "now" (unix seconds), for testing
export async function verifyToken(token, { publicKey, expectedAudience, minTrustScore, allowDeviceArch, now } = {}) {
  try {
    const pk = parsePublicKey(publicKey); // throws if missing/garbage

    // Fail closed on a malformed policy option — never silently skip enforcement.
    const perr = policyOptionError({ minTrustScore, allowDeviceArch });
    if (perr) return { valid: false, error: `invalid policy option: ${perr}` };

    if (typeof token !== 'string' || token.length === 0) {
      return { valid: false, error: 'token must be a non-empty string' };
    }
    // Exactly two segments. A `a.b.c` token must NOT verify by silently
    // ignoring the trailing junk — split('.') destructuring would do that.
    const parts = token.split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return { valid: false, error: 'malformed token (must be exactly payload.signature)' };
    }

    const payloadBytes = b64urlDecode(parts[0]);
    const signature = b64urlDecode(parts[1]);

    const sigOk = await ed.verify(signature, payloadBytes, pk);
    if (!sigOk) return { valid: false, error: 'signature invalid' };

    const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
    const ts = Number.isFinite(now) ? now : Math.floor(Date.now() / 1000);

    // SECURITY: a token with no usable expiry is treated as invalid, not
    // eternal. Every token we issue sets expires_at; a verified-signature token
    // lacking it is malformed and must be rejected (fail closed).
    if (!Number.isFinite(payload.expires_at)) {
      return { valid: false, payload, error: 'token missing valid expires_at' };
    }
    if (payload.expires_at < ts) {
      return { valid: false, payload, error: 'token expired' };
    }

    // --- Policy checks (signature already proven; these gate authorization) ---
    if (expectedAudience !== undefined && expectedAudience !== null) {
      if (payload.aud !== expectedAudience) {
        return { valid: false, payload, error: `audience mismatch (token aud=${JSON.stringify(payload.aud ?? null)})` };
      }
    }
    // Options already validated above (policyOptionError). Apply only when set.
    if (minTrustScore !== undefined && minTrustScore !== null) {
      const score = Number(payload.trust_score);
      if (!Number.isFinite(score) || score < minTrustScore) {
        return { valid: false, payload, error: `trust_score below minimum (${payload.trust_score} < ${minTrustScore})` };
      }
    }
    if (allowDeviceArch !== undefined && allowDeviceArch !== null) {
      if (!allowDeviceArch.includes(payload.device_arch)) {
        return { valid: false, payload, error: `device_arch not allowed (${payload.device_arch})` };
      }
    }

    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: `verify failed: ${err.message}` };
  }
}

function b64url(bytes) {
  return Buffer.from(bytes).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function b64urlDecode(s) {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
}

// Hash node identifier from submission for consistent IDing across retries.
//
// SECURITY: a client-supplied hardware_id is only used verbatim if it is a
// short, charset-restricted opaque token. Anything else is hashed, so an
// attacker can never get an arbitrary string echoed into a signed attestation
// payload. validateFingerprint() should already have rejected a malformed
// hardware_id before we get here; this is defense in depth.
const HWID_VERBATIM_PATTERN = /^[A-Za-z0-9_.:-]{16,128}$/;

export function deriveNodeId(fingerprint) {
  // Select explicitly (not `a || b`) so a falsy-but-present hardware_id is not
  // coalesced into hwid unexpectedly.
  const hwid = ('hardware_id' in fingerprint) ? fingerprint.hardware_id : fingerprint.hwid;
  if (typeof hwid === 'string' && HWID_VERBATIM_PATTERN.test(hwid)) {
    return hwid;
  }

  // Fallback: hash device fields into a fixed-width opaque ID. The FULL rejected
  // hwid is mixed in (not a prefix slice) so two distinct oversized IDs that
  // happen to share a prefix still produce distinct node IDs. sha512 handles
  // arbitrary-length input; the request body size is already capped server-side.
  const device = fingerprint.device || {};
  const fields = [
    device.device_model || device.model || '',
    device.device_arch || device.arch || '',
    device.device_family || device.family || '',
    device.cpu_serial || '',
    typeof hwid === 'string' ? hwid : '',
  ].join('|');

  return Buffer.from(sha512(new TextEncoder().encode(fields))).toString('hex').slice(0, 32);
}
