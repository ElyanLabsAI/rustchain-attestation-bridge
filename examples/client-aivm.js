// SPDX-License-Identifier: MIT
// Example: how a ChainGPT AIVM node (or any external system) would call the
// RustChain Attestation Bridge to prove its hardware is real (not a VM).
//
// Flow:
//   1. AIVM node runs the 6 hardware fingerprint checks locally
//      (using fingerprint_checks.py from RustChain, or a port to TS/Rust)
//   2. AIVM node POSTs the result to the bridge
//   3. Bridge validates, issues an Ed25519-signed attestation token
//   4. AIVM node embeds the token in subsequent transactions / API calls
//   5. Anyone (the chain, validators, RPC consumers) can verify the token
//      offline against the bridge's public key
//
// Run: node examples/client-aivm.js [bridge_url]
// Default bridge_url: http://localhost:3001

const bridgeUrl = process.argv[2] || 'http://localhost:3001';

// In a real AIVM node, this fingerprint object would come from running the
// 6 checks locally. Here we hand-build a sample that represents real hardware.
const sampleFingerprint = {
  hardware_id: 'aivm-node-bnb-mainnet-' + Date.now().toString(36),
  device: {
    device_family: 'x86_64',
    device_arch: 'modern',
    device_model: 'AMD EPYC 7763',
    cpu_serial: 'EPYC-7763-001',
  },
  checks: {
    anti_emulation: {
      passed: true,
      data: { vm_indicators: [] },
    },
    clock_drift: {
      passed: true,
      data: { cv: 0.087, samples: 1000 },
    },
    cache_timing: {
      passed: true,
      data: { l1_latency_ns: 1.2, l2_latency_ns: 4.8, l3_latency_ns: 14.6 },
    },
    simd_identity: {
      passed: true,
      data: { has_avx2: true, has_avx512: true },
    },
    thermal_drift: {
      passed: true,
      data: { cold_temp_c: 35, warm_temp_c: 68 },
    },
    instruction_jitter: {
      passed: true,
      data: { jitter_ns_p99: 2.1 },
    },
  },
};

async function main() {
  console.log('═══ AIVM Node — calling RustChain Attestation Bridge ═══');
  console.log(`Bridge URL: ${bridgeUrl}`);
  console.log('');

  // Step 1 — fetch bridge public key (cache this in production)
  console.log('Step 1 — fetch bridge public key for offline verification later');
  const pkRes = await fetch(`${bridgeUrl}/pubkey`);
  const pkData = await pkRes.json();
  console.log('  Bridge public key:', pkData.public_key_hex.slice(0, 24) + '...');
  console.log('');

  // Step 2 — submit fingerprint, request attestation
  console.log('Step 2 — submit fingerprint to /attest');
  console.log('  Hardware ID:', sampleFingerprint.hardware_id);
  console.log('  Device:', sampleFingerprint.device.device_model);

  const attRes = await fetch(`${bridgeUrl}/attest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(sampleFingerprint),
  });
  const att = await attRes.json();

  if (!att.ok) {
    console.error('✗ Attestation failed:', att.error);
    console.error('  Details:', att.details);
    process.exit(1);
  }

  console.log('  ✓ Attestation issued');
  console.log('  Trust score:', att.validation.score);
  console.log('  Token preview:', att.token.slice(0, 60) + '...');
  console.log('');

  // Step 3 — show how the AIVM node would use the token
  console.log('Step 3 — embed token in onward calls');
  console.log('  In production, an AIVM node would:');
  console.log('    a. Include the token in transaction metadata');
  console.log('    b. Send it as Authorization: Bearer <token> on AI inference requests');
  console.log('    c. Publish it alongside any reward claims');
  console.log('');

  // Step 4 — verify the token (any third party can do this)
  console.log('Step 4 — verify token via bridge');
  const verRes = await fetch(`${bridgeUrl}/verify/${att.token}`);
  const ver = await verRes.json();

  if (ver.ok && ver.valid) {
    console.log('  ✓ Token verified online');
    console.log('  Verified claims:', JSON.stringify(ver.payload, null, 2));
  } else {
    console.error('  ✗ Verification failed:', ver.error);
  }
  console.log('');

  console.log('═══ Done ═══');
  console.log('In production, third parties verify offline using the bridge public key —');
  console.log('no need to call the bridge again after the initial attestation.');
}

main().catch((err) => {
  console.error('✗ Example failed:', err.message);
  process.exit(1);
});
