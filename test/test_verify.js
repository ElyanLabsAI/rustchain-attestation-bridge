// SPDX-License-Identifier: MIT
// Tests for the standalone offline verifier + audience binding + Express
// middleware. No network, no server, no extra deps (mock req/res).
//
// Run: node test/test_verify.js

import assert from 'node:assert/strict';
import { Attestation, verifyToken, parsePublicKey } from '../src/attestation.js';
import { createVerifier, requireAttestation } from '../src/verify-middleware.js';

// ---- helpers ---------------------------------------------------------------

async function makeBridge() {
  const ed = await import('@noble/ed25519');
  const sha512 = (await import('@noble/hashes/sha512.js')).sha512;
  ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
  const privateKey = ed.utils.randomPrivateKey();
  const att = new Attestation({ privateKey, bridgeUrl: 'http://test-bridge' });
  const pubHex = await att.getPublicKeyHex();
  return { att, pubHex, ed };
}

// Minimal Express-style res mock that captures the last status + json body.
function mockRes() {
  return {
    statusCode: null,
    body: null,
    headers: {},
    status(code) { this.statusCode = code; return this; },
    json(obj) { this.body = obj; return this; },
    set(k, v) { this.headers[k] = v; return this; },
  };
}

async function runMiddleware(mw, req) {
  const res = mockRes();
  let nextCalled = false;
  await mw(req, res, () => { nextCalled = true; });
  return { res, nextCalled };
}

// ---- tests -----------------------------------------------------------------

console.log('Test 1: verifyToken validates with hex pubkey, rejects wrong key');
{
  const { att, pubHex } = await makeBridge();
  const { token } = await att.issue({ nodeId: 'node-a', deviceArch: 'g4', trustScore: 100 });

  const ok = await verifyToken(token, { publicKey: pubHex });
  assert.equal(ok.valid, true, 'correct pubkey should verify');
  assert.equal(ok.payload.node_id, 'node-a');

  const other = await makeBridge();
  const bad = await verifyToken(token, { publicKey: other.pubHex });
  assert.equal(bad.valid, false, 'wrong pubkey must NOT verify');
  assert.match(bad.error, /signature/);
}
console.log('  ✓ offline verify with hex pubkey; wrong key rejected');

console.log('Test 2: parsePublicKey accepts hex + Uint8Array, rejects junk');
{
  const { att } = await makeBridge();
  const pk = await att.getPublicKey();
  assert.ok(parsePublicKey(pk) instanceof Uint8Array, 'accepts 32-byte array');
  assert.ok(parsePublicKey(Buffer.from(pk).toString('hex')) instanceof Uint8Array, 'accepts hex');
  for (const junk of [undefined, null, '', 'xyz', 'ab', 123, new Uint8Array(31)]) {
    assert.throws(() => parsePublicKey(junk), `should reject ${JSON.stringify(junk)}`);
  }
}
console.log('  ✓ parsePublicKey validates key material');

console.log('Test 3: audience binding — match passes, mismatch fails');
{
  const { att, pubHex } = await makeBridge();
  const { token } = await att.issue({ nodeId: 'node-aud', deviceArch: 'modern', trustScore: 80, audience: 'x402.serviceA' });

  const right = await verifyToken(token, { publicKey: pubHex, expectedAudience: 'x402.serviceA' });
  assert.equal(right.valid, true, 'matching audience should pass');

  const wrong = await verifyToken(token, { publicKey: pubHex, expectedAudience: 'x402.serviceB' });
  assert.equal(wrong.valid, false, 'mismatched audience must fail (replay at another service)');
  assert.match(wrong.error, /audience mismatch/);

  // A token with NO aud presented to a verifier that requires one must fail.
  const { token: noAud } = await att.issue({ nodeId: 'n2', trustScore: 80 });
  const needsAud = await verifyToken(noAud, { publicKey: pubHex, expectedAudience: 'x402.serviceA' });
  assert.equal(needsAud.valid, false, 'no-aud token must fail when verifier requires an audience');

  // Backward compat: a verifier that does NOT ask for an audience ignores aud.
  const lax = await verifyToken(token, { publicKey: pubHex });
  assert.equal(lax.valid, true, 'verifier not checking audience still accepts an aud-bound token');
}
console.log('  ✓ audience binding enforced opt-in, backward compatible');

console.log('Test 4: minTrustScore + allowDeviceArch policy gates');
{
  const { att, pubHex } = await makeBridge();
  const { token } = await att.issue({ nodeId: 'g5-node', deviceArch: 'g5', trustScore: 33 });

  assert.equal((await verifyToken(token, { publicKey: pubHex, minTrustScore: 30 })).valid, true, '33 >= 30 passes');
  const lowTrust = await verifyToken(token, { publicKey: pubHex, minTrustScore: 50 });
  assert.equal(lowTrust.valid, false, '33 < 50 fails');
  assert.match(lowTrust.error, /trust_score below/);

  assert.equal((await verifyToken(token, { publicKey: pubHex, allowDeviceArch: ['g4', 'g5'] })).valid, true, 'g5 allowed');
  const badArch = await verifyToken(token, { publicKey: pubHex, allowDeviceArch: ['modern'] });
  assert.equal(badArch.valid, false, 'g5 not in [modern]');
  assert.match(badArch.error, /device_arch not allowed/);
}
console.log('  ✓ trust-score and device-arch policy gates');

console.log('Test 5: createVerifier from hex + fetched /pubkey');
{
  const { pubHex } = await makeBridge();
  const fromHex = await createVerifier({ publicKeyHex: pubHex });
  assert.ok(fromHex.publicKey instanceof Uint8Array, 'hex path builds a verifier');

  // Mock fetch returning the /pubkey shape.
  const fetchImpl = async (url) => {
    assert.match(url, /\/pubkey$/, 'should hit /pubkey');
    return { ok: true, json: async () => ({ ok: true, public_key_hex: pubHex, algorithm: 'Ed25519' }) };
  };
  const fromUrl = await createVerifier({ bridgeUrl: 'http://bridge/', fetchImpl });
  assert.ok(fromUrl.publicKey instanceof Uint8Array, 'url path builds a verifier');
}
console.log('  ✓ createVerifier from pinned hex and from /pubkey fetch');

console.log('Test 6: requireAttestation middleware — happy path attaches req.attestation');
{
  const { att, pubHex } = await makeBridge();
  const { token } = await att.issue({ nodeId: 'mw-node', deviceArch: 'modern', trustScore: 100, audience: 'svc1' });
  const verifier = await createVerifier({ publicKeyHex: pubHex });
  const mw = requireAttestation(verifier, { audience: 'svc1', minTrustScore: 50 });

  const req = { headers: { authorization: `Bearer ${token}` } };
  const { res, nextCalled } = await runMiddleware(mw, req);
  assert.equal(nextCalled, true, 'valid token should call next()');
  assert.equal(req.attestation.node_id, 'mw-node', 'verified payload attached to req');
  assert.equal(res.statusCode, null, 'no error response on success');
}
console.log('  ✓ middleware passes valid token and exposes claims');

console.log('Test 7: middleware — missing token 401, bad signature 401, policy 403');
{
  const { att, pubHex } = await makeBridge();
  const verifier = await createVerifier({ publicKeyHex: pubHex });

  // Missing token
  {
    const mw = requireAttestation(verifier);
    const { res, nextCalled } = await runMiddleware(mw, { headers: {} });
    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.error, 'attestation_required');
  }

  // Tampered token → 401 invalid
  {
    const { token } = await att.issue({ nodeId: 'x', trustScore: 100 });
    const tampered = token.slice(0, -2) + (token.endsWith('AA') ? 'BB' : 'AA');
    const mw = requireAttestation(verifier);
    const { res, nextCalled } = await runMiddleware(mw, { headers: { authorization: `Bearer ${tampered}` } });
    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.error, 'attestation_invalid');
  }

  // Valid signature but failing policy (audience mismatch) → 403 forbidden
  {
    const { token } = await att.issue({ nodeId: 'y', trustScore: 100, audience: 'svcA' });
    const mw = requireAttestation(verifier, { audience: 'svcB' });
    const { res, nextCalled } = await runMiddleware(mw, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 403, 'authenticated-but-unauthorized is 403');
    assert.equal(res.body.error, 'attestation_forbidden');
  }
}
console.log('  ✓ middleware status codes: 401 auth failures, 403 policy failures');

console.log('Test 8: malformed policy options FAIL CLOSED (no silent skip)');
{
  const { att, pubHex } = await makeBridge();
  const { token } = await att.issue({ nodeId: 'p', deviceArch: 'modern', trustScore: 100 });

  // minTrustScore as a string must not silently disable the gate.
  const badMin = await verifyToken(token, { publicKey: pubHex, minTrustScore: '50' });
  assert.equal(badMin.valid, false, 'string minTrustScore must fail closed');
  assert.match(badMin.error, /invalid policy/);

  // allowDeviceArch as a string (not array) must not silently allow everything.
  const badArch = await verifyToken(token, { publicKey: pubHex, allowDeviceArch: 'modern' });
  assert.equal(badArch.valid, false, 'non-array allowDeviceArch must fail closed');
  assert.match(badArch.error, /invalid policy/);

  // Empty allowlist is a config error, not "allow all".
  const emptyList = await verifyToken(token, { publicKey: pubHex, allowDeviceArch: [] });
  assert.equal(emptyList.valid, false, 'empty allowDeviceArch must fail closed');

  // requireAttestation rejects a bad policy at SETUP time (fail fast).
  const verifier = await createVerifier({ publicKeyHex: pubHex });
  assert.throws(() => requireAttestation(verifier, { minTrustScore: 'high' }), /minTrustScore/);
  assert.throws(() => requireAttestation(verifier, { allowDeviceArch: [] }), /allowDeviceArch/);
}
console.log('  ✓ malformed policy options fail closed at verify + setup');

console.log('Test 9: issue() rejects an oversized audience (no silent truncation)');
{
  const { att, pubHex } = await makeBridge();
  await assert.rejects(() => att.issue({ nodeId: 'x', audience: 'a'.repeat(201) }), /≤200|200 chars/);
  await assert.rejects(() => att.issue({ nodeId: 'x', audience: '' }), /non-empty/);
  await assert.rejects(() => att.issue({ nodeId: 'x', audience: 123 }), /string/);
  // A 200-char audience is accepted and bound exactly (not truncated).
  const aud = 'b'.repeat(200);
  const { token } = await att.issue({ nodeId: 'x', audience: aud, trustScore: 1 });
  const v = await verifyToken(token, { publicKey: pubHex, expectedAudience: aud });
  assert.equal(v.valid, true, 'exactly-200 audience round-trips');
}
console.log('  ✓ oversized audience rejected, boundary preserved');

console.log('\n✓ All verify/middleware tests passed');