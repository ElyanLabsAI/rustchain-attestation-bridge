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
app.disable('x-powered-by');

// Trust proxy is OFF by default. Enable it (BRIDGE_TRUST_PROXY=1, or a count /
// CIDR list) ONLY when the bridge actually sits behind a reverse proxy you
// control — otherwise req.ip can be spoofed via X-Forwarded-For. This matters
// for the rate limiter below, which keys on req.ip.
const trustProxy = process.env.BRIDGE_TRUST_PROXY;
if (trustProxy) {
  // Accept "1"/"true" as boolean, a number ("2"), or a comma list of proxies.
  if (trustProxy === '1' || trustProxy === 'true') app.set('trust proxy', true);
  else if (/^\d+$/.test(trustProxy)) app.set('trust proxy', Number(trustProxy));
  else app.set('trust proxy', trustProxy.split(',').map((s) => s.trim()));
}

// Body limit unchanged at 256kb — fingerprint payloads can be large (e.g. retro
// ROM data + per-check buffers). Don't tighten without evidence legit payloads fit.
app.use(express.json({ limit: '256kb' }));

// Log every request (basic visibility). SECURITY: never log the token segment of
// /verify/:token — a token is a bearer credential. Redact the path so tokens
// don't end up in plaintext logs.
app.use((req, _res, next) => {
  const safePath = req.path.startsWith('/verify/') ? '/verify/<redacted>' : req.path;
  console.log(`${new Date().toISOString()} ${req.method} ${safePath}`);
  next();
});

// Optional in-memory rate limiter — per-IP fixed window. OPT-IN (default OFF) so
// it never silently breaks a deployment behind a shared-IP proxy: enable with
// BRIDGE_RATE_LIMIT=1, and set BRIDGE_TRUST_PROXY appropriately so req.ip is the
// real client. Per-process and in-memory — fine as a basic flood guard on a
// single instance, NOT a substitute for a real gateway limiter across a fleet.
const RATE_WINDOW_MS = 60_000;
const RATE_ENABLED = process.env.BRIDGE_RATE_LIMIT === '1' || process.env.BRIDGE_RATE_LIMIT === 'true';
const RATE_MAX = (() => {
  const parsed = Number(process.env.BRIDGE_RATE_MAX);
  // Validate: a positive finite integer. Bad/missing values fall back to 60 so a
  // typo can't silently disable limiting (NaN/Infinity) or reject everything (<=0).
  return Number.isInteger(parsed) && parsed > 0 ? parsed : 60;
})();
const rateHits = new Map(); // ip -> { count, windowStart }

function rateLimit(req, res, next) {
  if (!RATE_ENABLED) return next();
  try {
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    const now = Date.now();
    let entry = rateHits.get(ip);
    if (!entry || now - entry.windowStart >= RATE_WINDOW_MS) {
      entry = { count: 0, windowStart: now };
      rateHits.set(ip, entry);
    }
    entry.count += 1;
    if (entry.count > RATE_MAX) {
      const retryMs = RATE_WINDOW_MS - (now - entry.windowStart);
      res.set('Retry-After', String(Math.ceil(retryMs / 1000)));
      return res.status(429).json({ ok: false, error: 'rate_limited' });
    }
  } catch {
    // bookkeeping failure must not block legitimate traffic
  }
  next();
}

// Opportunistic cleanup so the Map can't grow unbounded under churned IPs.
// Only schedule it when the limiter is actually enabled.
if (RATE_ENABLED) {
  setInterval(() => {
    const cutoff = Date.now() - RATE_WINDOW_MS;
    for (const [ip, entry] of rateHits) {
      if (entry.windowStart < cutoff) rateHits.delete(ip);
    }
  }, RATE_WINDOW_MS).unref();
}

// POST /attest — submit fingerprint data, get attestation token
app.post('/attest', rateLimit, async (req, res) => {
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

    // Optional audience binding: the submitter may request a token scoped to a
    // specific recipient/service (e.g. an x402 endpoint id). A recipient that
    // checks the audience then rejects tokens minted for a different recipient.
    let audience;
    if (fingerprint.audience !== undefined && fingerprint.audience !== null) {
      if (typeof fingerprint.audience !== 'string' || fingerprint.audience.length === 0 || fingerprint.audience.length > 200) {
        return res.status(400).json({ ok: false, error: 'invalid_audience', hint: 'audience must be a non-empty string ≤200 chars' });
      }
      audience = fingerprint.audience;
    }

    // Issue token
    const result = await attestation.issue({
      nodeId,
      hardwareClass: 'real_hardware', // passed validation
      deviceArch: arch,
      trustScore: validation.score,
      audience,
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
    // Log full detail server-side; return an opaque error to the client so we
    // don't leak stack/internal-message detail to untrusted callers.
    console.error('attest error:', err);
    res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// GET /verify/:token — verify a previously-issued token
app.get('/verify/:token', rateLimit, async (req, res) => {
  try {
    const result = await attestation.verify(req.params.token);
    if (!result.valid) {
      return res.status(401).json({ ok: false, error: result.error, payload: result.payload });
    }
    res.json({ ok: true, valid: true, payload: result.payload });
  } catch (err) {
    console.error('verify error:', err);
    res.status(500).json({ ok: false, error: 'internal_error' });
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
