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
  async issue({ nodeId, hardwareClass, deviceArch, trustScore, ttlSeconds = ATTESTATION_TTL_SECONDS }) {
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

    const payloadJson = JSON.stringify(payload);
    const payloadBytes = new TextEncoder().encode(payloadJson);
    const signature = await ed.sign(payloadBytes, this._privateKey);

    return {
      token: `${b64url(payloadBytes)}.${b64url(signature)}`,
      payload,
    };
  }

  // Verify a token. Returns { valid, payload, error }.
  async verify(token, { publicKey = null } = {}) {
    try {
      const [payloadB64, sigB64] = token.split('.');
      if (!payloadB64 || !sigB64) {
        return { valid: false, error: 'malformed token (must have payload.signature)' };
      }

      const payloadBytes = b64urlDecode(payloadB64);
      const signature = b64urlDecode(sigB64);
      const pk = publicKey || (await this.getPublicKey());

      const valid = await ed.verify(signature, payloadBytes, pk);
      if (!valid) return { valid: false, error: 'signature invalid' };

      const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
      const now = Math.floor(Date.now() / 1000);
      if (payload.expires_at && payload.expires_at < now) {
        return { valid: false, payload, error: 'token expired' };
      }

      return { valid: true, payload };
    } catch (err) {
      return { valid: false, error: `verify failed: ${err.message}` };
    }
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
export function deriveNodeId(fingerprint) {
  const hwid = fingerprint.hardware_id || fingerprint.hwid;
  if (hwid && hwid.length >= 16) return hwid;

  // Fallback: hash device fields
  const device = fingerprint.device || {};
  const fields = [
    device.device_model || device.model || '',
    device.device_arch || device.arch || '',
    device.device_family || device.family || '',
    device.cpu_serial || '',
  ].join('|');

  return Buffer.from(sha512(new TextEncoder().encode(fields))).toString('hex').slice(0, 32);
}
