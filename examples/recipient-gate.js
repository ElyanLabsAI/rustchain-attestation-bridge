// Example: the RECIPIENT side of the engagement demo.
//
// "An agent makes an x402-paid request; the recipient validates the sender's
//  RustChain attestation before accepting."
//
// This spins up a tiny recipient service that gates a paid route with
// requireAttestation(), then plays three requests against it:
//   1. a sender with a valid, audience-bound attestation token  → 200
//   2. the same token replayed against a DIFFERENT service       → 403
//   3. a request with no token at all                            → 401
//
// In production the recipient pins the bridge's public key (publicKeyHex) and
// verifies fully offline — no call back to the bridge per request.
//
// Run: node examples/recipient-gate.js

import express from 'express';
import { Attestation } from '../src/attestation.js';
import { createVerifier, requireAttestation } from '../src/verify-middleware.js';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512.js';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const THIS_SERVICE = 'x402.payments.example';

async function main() {
  // --- The bridge (here in-process; normally a separate deployment) ---------
  const privateKey = ed.utils.randomPrivateKey();
  const bridge = new Attestation({ privateKey, bridgeUrl: 'http://bridge.local' });
  const pubHex = await bridge.getPublicKeyHex();

  // --- The recipient service: pin the bridge pubkey, gate the route ---------
  const verifier = await createVerifier({ publicKeyHex: pubHex }); // offline, no network
  const app = express();
  app.post(
    '/x402/charge',
    requireAttestation(verifier, { audience: THIS_SERVICE, minTrustScore: 50 }),
    (req, res) => {
      res.json({ ok: true, charged_by: req.attestation.node_id, device: req.attestation.device_arch });
    },
  );

  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  const base = `http://localhost:${server.address().port}`;
  console.log(`Recipient service listening at ${base} (audience=${THIS_SERVICE})\n`);

  // A sender attests and gets a token scoped to THIS recipient.
  const goodToken = (await bridge.issue({
    nodeId: 'aivm-node-epyc-7763-001',
    deviceArch: 'modern',
    trustScore: 100,
    audience: THIS_SERVICE,
  })).token;

  // The same hardware, but a token minted for a DIFFERENT recipient.
  const wrongAudToken = (await bridge.issue({
    nodeId: 'aivm-node-epyc-7763-001',
    deviceArch: 'modern',
    trustScore: 100,
    audience: 'x402.somewhere.else',
  })).token;

  const charge = (token) =>
    fetch(`${base}/x402/charge`, {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }).then(async (r) => ({ status: r.status, body: await r.json() }));

  console.log('1) Valid, audience-bound token:');
  console.log('  ', JSON.stringify(await charge(goodToken)));

  console.log('2) Token replayed from another service (wrong audience):');
  console.log('  ', JSON.stringify(await charge(wrongAudToken)));

  console.log('3) No token at all:');
  console.log('  ', JSON.stringify(await charge(null)));

  server.close();
  console.log('\nDone — recipient enforced attestation + audience binding fully offline.');
}

main().catch((err) => {
  console.error('✗ Example failed:', err.message);
  process.exit(1);
});
