// SPDX-License-Identifier: MIT
// Fingerprint validator — server-side checks on submitted hardware fingerprint
// data. Mirrors the logic in RustChain's fingerprint_checks.py (the 6-check
// hardware-attestation spec used by all RustChain miners).
//
// Six checks:
// 1. Clock-Skew & Oscillator Drift  — real silicon has CV > 0.0001
// 2. Cache Timing Fingerprint       — L1/L2/L3 latency tone
// 3. SIMD Unit Identity             — pipeline depth + bias profile
// 4. Thermal Drift Entropy          — physical heat curves
// 5. Instruction Path Jitter        — cycle-level jitter signatures
// 6. Anti-Emulation Behavioral      — VM/hypervisor detection
//
// This validator does NOT run the checks itself (those must run on the actual
// hardware). It validates that the submitted RESULTS are well-formed, internally
// consistent, and don't show telltale signs of forgery.

export function validateFingerprint(fingerprint) {
  const errors = [];
  const warnings = [];

  if (!fingerprint || typeof fingerprint !== 'object') {
    return { valid: false, errors: ['fingerprint must be an object'], warnings: [] };
  }

  const checks = fingerprint.checks;
  if (!checks || typeof checks !== 'object') {
    return { valid: false, errors: ['fingerprint.checks missing'], warnings: [] };
  }

  // Required: anti_emulation must be present and pass
  const antiEmu = checks.anti_emulation;
  if (!antiEmu) {
    errors.push('checks.anti_emulation missing');
  } else if (antiEmu.passed === false) {
    const indicators = antiEmu.data?.vm_indicators || [];
    errors.push(`vm_detected: ${JSON.stringify(indicators)}`);
  }

  // Required: clock_drift must show real-hardware variance (CV > 0.0001)
  const clock = checks.clock_drift;
  if (!clock) {
    errors.push('checks.clock_drift missing');
  } else {
    const cv = clock.data?.cv;
    if (typeof cv !== 'number') {
      errors.push('checks.clock_drift.data.cv missing or not a number');
    } else if (cv < 0.0001) {
      errors.push(`timing_too_uniform: cv=${cv} (real silicon has cv > 0.0001)`);
    }
  }

  // Optional but recommended: other 4 checks
  const optionalChecks = ['cache_timing', 'simd_identity', 'thermal_drift', 'instruction_jitter'];
  for (const name of optionalChecks) {
    const c = checks[name];
    if (!c) {
      warnings.push(`checks.${name} not provided (recommended for higher trust score)`);
    } else if (c.passed === false) {
      warnings.push(`${name} failed: ${JSON.stringify(c.data || {}).slice(0, 200)}`);
    }
  }

  // Hardware ID consistency
  const hardwareId = fingerprint.hardware_id || fingerprint.hwid;
  if (hardwareId && (typeof hardwareId !== 'string' || hardwareId.length < 16)) {
    errors.push('hardware_id must be a string of at least 16 chars');
  }

  // Optional ROM fingerprint check (PowerPC, 68K, Amiga retro hardware)
  const romCheck = checks.rom_fingerprint;
  if (romCheck && romCheck.passed === false) {
    const reason = romCheck.data?.reason || 'unknown';
    if (reason.includes('known_emulator_rom')) {
      errors.push(`emulator_rom_detected: ${reason}`);
    } else if (reason.includes('rom_clustering')) {
      warnings.push(`rom_clustering_detected: ${reason}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    score: computeTrustScore(checks, errors.length, warnings.length),
  };
}

// Trust score: 0-100 based on how many of the 6 checks were submitted + passed.
function computeTrustScore(checks, errorCount, warningCount) {
  if (errorCount > 0) return 0;
  const sixChecks = ['clock_drift', 'cache_timing', 'simd_identity', 'thermal_drift', 'instruction_jitter', 'anti_emulation'];
  const passed = sixChecks.filter((name) => checks[name]?.passed === true).length;
  return Math.round((passed / 6) * 100);
}

// Classify the device based on fingerprint metadata + check results.
export function classifyDevice(fingerprint) {
  const device = fingerprint.device || {};
  const family = device.device_family || device.family || 'unknown';
  const arch = device.device_arch || device.arch || 'unknown';
  const model = device.device_model || device.model || 'unknown';

  return { family, arch, model };
}
