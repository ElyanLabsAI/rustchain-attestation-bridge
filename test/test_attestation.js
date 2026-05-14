// Round-trip test: keygen → server start → submit valid fingerprint → verify
// token → submit invalid (VM) fingerprint → confirm rejection → verify tampered
// token rejected.
//
// Run: npm test  (assumes server is running on PORT from .env, default 3001)

import assert from 'node:assert/strict';
import { Attestation, deriveNodeId } from '../src/attestation.js';
import { validateFingerprint } from '../src/fingerprint.js';

console.log('Test 1: validateFingerprint accepts well-formed real-hardware data');
{
  const real = {
    hardware_id: 'aaaaaaaaaaaaaaaa-test-hw',
    device: { device_family: 'x86_64', device_arch: 'modern' },
    checks: {
      anti_emulation: { passed: true },
      clock_drift: { passed: true, data: { cv: 0.08 } },
      cache_timing: { passed: true },
      simd_identity: { passed: true },
      thermal_drift: { passed: true },
      instruction_jitter: { passed: true },
    },
  };
  const v = validateFingerprint(real);
  assert.equal(v.valid, true, 'real hardware should validate');
  assert.equal(v.errors.length, 0, 'no errors expected');
  assert.equal(v.score, 100, 'all 6 checks pass = 100 score');
}
console.log('  ✓ valid hardware accepted, score=100');

console.log('Test 2: validateFingerprint rejects VM-detected submission');
{
  const vm = {
    hardware_id: 'vm-test-bbbbbbbbbbbbbbbb',
    device: { device_family: 'x86_64' },
    checks: {
      anti_emulation: { passed: false, data: { vm_indicators: ['cpuinfo:hypervisor'] } },
      clock_drift: { passed: true, data: { cv: 0.05 } },
    },
  };
  const v = validateFingerprint(vm);
  assert.equal(v.valid, false, 'VM should NOT validate');
  assert.ok(v.errors.some((e) => e.includes('vm_detected')), 'error should mention vm_detected');
  assert.equal(v.score, 0, 'errors → 0 score');
}
console.log('  ✓ VM rejected with vm_detected error');

console.log('Test 3: validateFingerprint rejects too-uniform timing (synthetic clock)');
{
  const synthetic = {
    hardware_id: 'synth-test-cccccccccccccccc',
    device: { device_family: 'x86_64' },
    checks: {
      anti_emulation: { passed: true },
      clock_drift: { passed: true, data: { cv: 0.00001 } }, // way too low
    },
  };
  const v = validateFingerprint(synthetic);
  assert.equal(v.valid, false, 'synthetic clock should NOT validate');
  assert.ok(v.errors.some((e) => e.includes('timing_too_uniform')), 'error should mention timing_too_uniform');
}
console.log('  ✓ too-uniform timing rejected');

console.log('Test 4: Attestation issue + verify roundtrip');
{
  // Generate ephemeral keypair for test
  const ed = await import('@noble/ed25519');
  const sha512 = (await import('@noble/hashes/sha512.js')).sha512;
  ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

  const privateKey = ed.utils.randomPrivateKey();
  const att = new Attestation({ privateKey, bridgeUrl: 'http://test' });

  const issued = await att.issue({
    nodeId: 'test-node',
    hardwareClass: 'real_hardware',
    deviceArch: 'g4',
    trustScore: 100,
  });

  assert.ok(issued.token, 'should return token string');
  assert.match(issued.token, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, 'token format payload.signature');

  const verified = await att.verify(issued.token);
  assert.equal(verified.valid, true, 'untampered token should verify');
  assert.equal(verified.payload.node_id, 'test-node');
  assert.equal(verified.payload.hardware_class, 'real_hardware');
  assert.equal(verified.payload.device_arch, 'g4');
  assert.equal(verified.payload.trust_score, 100);
}
console.log('  ✓ token issued + verified');

console.log('Test 5: Tampered token rejected');
{
  const ed = await import('@noble/ed25519');
  const sha512 = (await import('@noble/hashes/sha512.js')).sha512;
  ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

  const privateKey = ed.utils.randomPrivateKey();
  const att = new Attestation({ privateKey, bridgeUrl: 'http://test' });

  const { token } = await att.issue({ nodeId: 'tamper-test', hardwareClass: 'real_hardware' });
  const tampered = token.slice(0, -1) + (token.slice(-1) === 'X' ? 'Y' : 'X');

  const verified = await att.verify(tampered);
  assert.equal(verified.valid, false, 'tampered token should NOT verify');
  assert.ok(verified.error?.includes('signature') || verified.error?.includes('verify'), 'error should mention signature');
}
console.log('  ✓ tampered token rejected');

console.log('Test 6: Expired token rejected');
{
  const ed = await import('@noble/ed25519');
  const sha512 = (await import('@noble/hashes/sha512.js')).sha512;
  ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

  const privateKey = ed.utils.randomPrivateKey();
  const att = new Attestation({ privateKey, bridgeUrl: 'http://test' });

  const { token } = await att.issue({
    nodeId: 'expired-test',
    hardwareClass: 'real_hardware',
    ttlSeconds: -1, // already expired
  });

  const verified = await att.verify(token);
  assert.equal(verified.valid, false, 'expired token should NOT verify');
  assert.ok(verified.error?.includes('expired'), 'error should mention expired');
}
console.log('  ✓ expired token rejected');

console.log('Test 7: deriveNodeId returns stable ID for same fingerprint');
{
  const fp = {
    hardware_id: 'stable-test-dddddddddddddddd',
    device: { device_model: 'X', device_arch: 'modern' },
  };
  const id1 = deriveNodeId(fp);
  const id2 = deriveNodeId(fp);
  assert.equal(id1, id2, 'same fingerprint → same node_id');
  assert.equal(id1, 'stable-test-dddddddddddddddd', 'should use hardware_id when present');
}
console.log('  ✓ deriveNodeId stable');

console.log('\n✓ All 7 tests passed');
