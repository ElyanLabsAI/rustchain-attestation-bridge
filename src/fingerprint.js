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

// Floor for the clock-drift coefficient of variation. Below this reads as
// synthetic/too-uniform timing. There is deliberately NO upper bound: CV has no
// universal ceiling and a noisy-but-legitimate environment can measure high, so
// an arbitrary cap would reject real hardware.
const CLOCK_CV_MIN = 0.0001;

// Bounds on a client-supplied hardware_id. It ends up inside a signed token and
// is used as a map/log key, so it must be a short, opaque, charset-restricted
// identifier — not an arbitrary attacker-controlled blob.
const HWID_MIN_LEN = 16;
const HWID_MAX_LEN = 128;
const HWID_PATTERN = /^[A-Za-z0-9_.:-]+$/;

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

  // Required: anti_emulation must be present and EXPLICITLY pass.
  // SECURITY: we require passed === true, not "not false". A submission that
  // omits `passed` (or sends a non-boolean) must NOT slip through — this is the
  // exact "trust passed:true blindly" regression BuilderFred's audit caught on
  // the main node. Fail closed.
  const antiEmu = checks.anti_emulation;
  if (!antiEmu || typeof antiEmu !== 'object') {
    errors.push('checks.anti_emulation missing');
  } else if (antiEmu.passed !== true) {
    const indicators = Array.isArray(antiEmu.data?.vm_indicators)
      ? antiEmu.data.vm_indicators
      : [];
    errors.push(`vm_detected_or_unproven: ${JSON.stringify(indicators)}`);
  }

  // Required: clock_drift must show real-hardware variance (CV > 0.0001).
  // SECURITY: written as a positive finite-number assertion. A bare `cv < 0.0001`
  // gate is bypassed by NaN/Infinity (every comparison with NaN is false), which
  // would let synthetic timing pass. Number.isFinite() rejects NaN, ±Infinity,
  // and non-numbers in one check, so malformed input fails closed.
  const clock = checks.clock_drift;
  if (!clock || typeof clock !== 'object') {
    errors.push('checks.clock_drift missing');
  } else {
    const cv = clock.data?.cv;
    if (!Number.isFinite(cv)) {
      errors.push('checks.clock_drift.data.cv missing or not a finite number');
    } else if (cv < CLOCK_CV_MIN) {
      errors.push(`timing_too_uniform: cv=${cv} (real silicon has cv > ${CLOCK_CV_MIN})`);
    }
  }

  // Optional but recommended: other 4 checks. Only a check that EXPLICITLY
  // reports passed === true counts toward the trust score (see computeTrustScore);
  // here we just surface visibility on what was provided vs. failed.
  const optionalChecks = ['cache_timing', 'simd_identity', 'thermal_drift', 'instruction_jitter'];
  for (const name of optionalChecks) {
    const c = checks[name];
    if (!c || typeof c !== 'object') {
      warnings.push(`checks.${name} not provided (recommended for higher trust score)`);
    } else if (c.passed !== true) {
      warnings.push(`${name} failed_or_unproven: ${JSON.stringify(c.data || {}).slice(0, 200)}`);
    }
  }

  // Hardware ID consistency. If supplied, it must be a short, charset-restricted
  // opaque identifier — it gets embedded in a signed token and used as a key.
  // Select explicitly (not `a || b`) so a falsy-but-present value like
  // hardware_id: '' or 0 is still caught by the type/length checks below rather
  // than silently coalescing past them.
  const hardwareId = ('hardware_id' in fingerprint) ? fingerprint.hardware_id : fingerprint.hwid;
  if (hardwareId !== undefined && hardwareId !== null) {
    if (typeof hardwareId !== 'string') {
      errors.push('hardware_id must be a string');
    } else if (hardwareId.length < HWID_MIN_LEN || hardwareId.length > HWID_MAX_LEN) {
      errors.push(`hardware_id must be ${HWID_MIN_LEN}-${HWID_MAX_LEN} chars (got ${hardwareId.length})`);
    } else if (!HWID_PATTERN.test(hardwareId)) {
      errors.push('hardware_id contains illegal characters (allowed: A-Z a-z 0-9 _ . : -)');
    }
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
