/**
 * SentinelGate — Layer 1: Cryptographic Ingress Verification
 * Enforces NIST SP 800-207 Zero-Trust Authentication Principles:
 * - Constant-time SHA-256 API Key verification (prevents timing side-channel attacks)
 * - HMAC-SHA256 signature verification over canonical HTTP request payload
 * - Replay attack prevention with sliding timestamp window (300s) + nonce ring buffer
 */

const crypto = require('crypto');

class CryptoAuth {
  constructor(options = {}) {
    this.maxTimestampSkewSec = options.maxTimestampSkewSec || 300; // 5-minute sliding window
    this.seenNonces = new Map(); // nonce -> expiry timestamp
    this.nonceCleanupInterval = setInterval(() => this._cleanupNonces(), 60000);
    if (this.nonceCleanupInterval.unref) this.nonceCleanupInterval.unref();

    // Default registered clients (keyHash -> { clientId, role, secretKey })
    this.clients = new Map();
  }

  registerClient(clientId, rawApiKey, secretKey, role = 'standard') {
    const keyHash = this.hashApiKey(rawApiKey);
    this.clients.set(keyHash, {
      clientId,
      role,
      secretKey,
      registeredAt: Date.now()
    });
    return { clientId, keyHash };
  }

  hashApiKey(rawKey) {
    return crypto.createHash('sha256').update(String(rawKey)).digest('hex');
  }

  /**
   * Verify API Key with constant-time equality
   */
  authenticateApiKey(providedKey) {
    if (!providedKey) {
      return { authenticated: false, error: 'MISSING_API_KEY' };
    }

    const providedHash = this.hashApiKey(providedKey);
    const providedBuffer = Buffer.from(providedHash, 'hex');

    for (const [storedHash, client] of this.clients.entries()) {
      const storedBuffer = Buffer.from(storedHash, 'hex');
      if (storedBuffer.length === providedBuffer.length &&
          crypto.timingSafeEqual(storedBuffer, providedBuffer)) {
        return {
          authenticated: true,
          client: {
            clientId: client.clientId,
            role: client.role,
            secretKey: client.secretKey
          }
        };
      }
    }

    return { authenticated: false, error: 'INVALID_API_KEY' };
  }

  /**
   * Verify HMAC-SHA256 signature
   * Header format: t={timestamp},n={nonce},v1={signature_hex}
   */
  verifyRequestSignature(secretKey, rawBody, signatureHeader) {
    if (!signatureHeader) {
      return { verified: false, error: 'MISSING_SIGNATURE_HEADER' };
    }

    const parts = {};
    signatureHeader.split(',').forEach(item => {
      const [k, v] = item.split('=');
      if (k && v) parts[k.trim()] = v.trim();
    });

    const timestamp = parseInt(parts.t, 10);
    const nonce = parts.n;
    const receivedSig = parts.v1;

    if (!timestamp || !nonce || !receivedSig) {
      return { verified: false, error: 'MALFORMED_SIGNATURE_HEADER' };
    }

    // 1. Check timestamp skew (Replay Defense)
    const nowSec = Math.floor(Date.now() / 1000);
    const skew = Math.abs(nowSec - timestamp);
    if (skew > this.maxTimestampSkewSec) {
      return { verified: false, error: 'TIMESTAMP_EXPIRED', skewSec: skew };
    }

    // 2. Check nonce uniqueness (Anti-Replay)
    if (this.seenNonces.has(nonce)) {
      return { verified: false, error: 'REPLAY_ATTACK_DETECTED' };
    }

    // 3. Recompute HMAC-SHA256 over canonical string: timestamp.nonce.body
    const canonicalPayload = `${timestamp}.${nonce}.${typeof rawBody === 'string' ? rawBody : JSON.stringify(rawBody || '')}`;
    const expectedSig = crypto
      .createHmac('sha256', secretKey)
      .update(canonicalPayload)
      .digest('hex');

    const expectedBuffer = Buffer.from(expectedSig, 'hex');
    const receivedBuffer = Buffer.from(receivedSig, 'hex');

    if (expectedBuffer.length !== receivedBuffer.length ||
        !crypto.timingSafeEqual(expectedBuffer, receivedBuffer)) {
      return { verified: false, error: 'SIGNATURE_MISMATCH' };
    }

    // Record nonce until window expiration
    this.seenNonces.set(nonce, nowSec + this.maxTimestampSkewSec);

    return { verified: true, timestamp, nonce };
  }

  /**
   * Helper to sign a request (for test suites and clients)
   */
  createSignature(secretKey, rawBody, customNonce = null, customTimestamp = null) {
    const timestamp = customTimestamp || Math.floor(Date.now() / 1000);
    const nonce = customNonce || crypto.randomBytes(12).toString('hex');
    const canonicalPayload = `${timestamp}.${nonce}.${typeof rawBody === 'string' ? rawBody : JSON.stringify(rawBody || '')}`;
    const sig = crypto.createHmac('sha256', secretKey).update(canonicalPayload).digest('hex');
    return `t=${timestamp},n=${nonce},v1=${sig}`;
  }

  _cleanupNonces() {
    const nowSec = Math.floor(Date.now() / 1000);
    for (const [nonce, expiry] of this.seenNonces.entries()) {
      if (nowSec > expiry) {
        this.seenNonces.delete(nonce);
      }
    }
  }

  destroy() {
    clearInterval(this.nonceCleanupInterval);
  }
}

module.exports = CryptoAuth;
