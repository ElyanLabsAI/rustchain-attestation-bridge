// Generate a fresh Ed25519 keypair for the bridge. Run once at setup; save the
// private key to .env (never commit) and publish the public key for offline
// verification.
//
// Usage: node src/keygen.js

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512.js';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const privateKey = ed.utils.randomPrivateKey();
const publicKey = await ed.getPublicKey(privateKey);

console.log('═══ NEW BRIDGE KEYPAIR ═══');
console.log('');
console.log('Private key (KEEP SECRET — paste into .env):');
console.log(`BRIDGE_PRIVATE_KEY=${Buffer.from(privateKey).toString('hex')}`);
console.log('');
console.log('Public key (publish this — used for offline token verification):');
console.log(`BRIDGE_PUBLIC_KEY=${Buffer.from(publicKey).toString('hex')}`);
console.log('');
console.log('Both keys are 32 bytes / 64 hex chars.');
