// SPDX-License-Identifier: MIT
// RustChain Attestation Bridge — HTTP service.
//
// External nodes (ChainGPT AIVM, any DePIN system) submit hardware fingerprint
// data and receive signed attestation tokens proving real-hardware authenticity.
// Anyone can verify a token offline against the bridge's published public key.
//
// Run:  node --env-file=.env src/server.js
// Endpoints:
//   POST /attest     — submit fingerprint, get token
//   GET  /verify/:token — verify a previously-issued token
//   GET  /pubkey     — return bridge public key (hex)
//   GET  /health     — health check

import express from 'express';
import { Attestation, deriveNodeId } from './attestation.js';
import { validateFingerprint, classifyDevice } from './fingerprint.js';

const port = process.env.PORT || 3000;
const bridgeUrl = process.env.BRIDGE_URL || `http://localhost:${port}`;

const privateKeyHex = process.env.BRIDGE_PRIVATE_KEY;
if (!privateKeyHex) {
  console.error('✗ BRIDGE_PRIVATE_KEY not set. Run `npm run keygen` and paste into .env.');
  process.exit(1);
}
if (privateKeyHex.length !== 64) {
  console.error(`✗ BRIDGE_PRIVATE_KEY must be 64 hex chars (got ${privateKeyHex.length})`);
  process.exit(1);
}

const privateKey = Uint8Array.from(Buffer.from(privateKeyHex, 'hex'));
const attestation = new Attestation({ privateKey, bridgeUrl });

const app = express();
app.use(express.json({ limit: '256kb' }));

// Log every request (basic visibility)
app.use((req, _res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// POST /attest — submit fingerprint data, get attestation token
app.post('/attest', async (req, res) => {
  try {
    const fingerprint = req.body;

    // Validate the submission
    const validation = validateFingerprint(fingerprint);
    if (!validation.valid) {
      return res.status(400).json({
        ok: false,
        error: 'fingerprint_validation_failed',
        details: validation.errors,
        warnings: validation.warnings,
      });
    }

    // Derive a stable node ID from the fingerprint
    const nodeId = deriveNodeId(fingerprint);

    // Classify the device
    const { family, arch, model } = classifyDevice(fingerprint);

    // Issue token
    const result = await attestation.issue({
      nodeId,
      hardwareClass: 'real_hardware', // passed validation
      deviceArch: arch,
      trustScore: validation.score,
    });

    res.json({
      ok: true,
      token: result.token,
      payload: result.payload,
      device: { family, arch, model },
      validation: {
        score: validation.score,
        warnings: validation.warnings,
      },
    });
  } catch (err) {
    console.error('attest error:', err);
    res.status(500).json({ ok: false, error: 'internal_error', message: err.message });
  }
});

// GET /verify/:token — verify a previously-issued token
app.get('/verify/:token', async (req, res) => {
  try {
    const result = await attestation.verify(req.params.token);
    if (!result.valid) {
      return res.status(401).json({ ok: false, error: result.error, payload: result.payload });
    }
    res.json({ ok: true, valid: true, payload: result.payload });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'internal_error', message: err.message });
  }
});

// GET /pubkey — return bridge public key (hex) for offline verification
app.get('/pubkey', async (_req, res) => {
  const hex = await attestation.getPublicKeyHex();
  res.json({ ok: true, public_key_hex: hex, algorithm: 'Ed25519' });
});

// GET /health — basic health check
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'rustchain-attestation-bridge',
    version: '0.0.1',
    bridge_url: bridgeUrl,
  });
});

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ ok: false, error: 'not_found' });
});

app.listen(port, () => {
  console.log(`╔══════════════════════════════════════════════╗`);
  console.log(`║ RustChain Attestation Bridge — listening      ║`);
  console.log(`║ http://localhost:${port}                            ║`);
  console.log(`║                                              ║`);
  console.log(`║ POST /attest      submit fingerprint         ║`);
  console.log(`║ GET  /verify/:t   verify token               ║`);
  console.log(`║ GET  /pubkey      bridge public key          ║`);
  console.log(`║ GET  /health      health check               ║`);
  console.log(`╚══════════════════════════════════════════════╝`);
});
