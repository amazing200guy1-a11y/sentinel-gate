/**
 * SentinelGate — Layer 2: Microsecond Token-Bucket Rate Limiter
 * In-memory high-throughput sliding window limiter.
 * Execution latency: < 0.1ms per check.
 */

class TokenBucketRateLimiter {
  constructor(options = {}) {
    // Default: 100 requests per minute with a burst allowance of 20
    this.defaultCapacity = options.capacity || 20;
    this.defaultRefillRatePerSec = options.refillRatePerSec || (100 / 60); // tokens/sec

    // Tier presets (role -> { capacity, refillRatePerSec })
    this.tierConfigs = {
      standard: { capacity: 30, refillRatePerSec: 1.0 },    // ~60 req/min, burst 30
      premium:  { capacity: 150, refillRatePerSec: 10.0 },  // ~600 req/min, burst 150
      internal: { capacity: 1000, refillRatePerSec: 100.0 } // high-throughput internal microservices
    };

    // Client buckets: clientId -> { tokens, lastRefillTimeMs, capacity, refillRatePerSec }
    this.buckets = new Map();

    // Auto cleanup of idle buckets every 5 minutes
    this.cleanupTimer = setInterval(() => this._cleanupIdle(), 300000);
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  getBucket(clientId, role = 'standard') {
    let bucket = this.buckets.get(clientId);
    const now = Date.now();

    if (!bucket) {
      const config = this.tierConfigs[role] || this.tierConfigs.standard;
      bucket = {
        tokens: config.capacity,
        lastRefillTimeMs: now,
        capacity: config.capacity,
        refillRatePerSec: config.refillRatePerSec
      };
      this.buckets.set(clientId, bucket);
    } else {
      // Refill tokens based on elapsed time
      const elapsedSec = (now - bucket.lastRefillTimeMs) / 1000;
      if (elapsedSec > 0) {
        bucket.tokens = Math.min(
          bucket.capacity,
          bucket.tokens + elapsedSec * bucket.refillRatePerSec
        );
        bucket.lastRefillTimeMs = now;
      }
    }

    return bucket;
  }

  /**
   * Consume tokens for a request.
   * Returns: { allowed: boolean, remaining: number, resetInSec: number, limit: number }
   */
  consume(clientId, role = 'standard', cost = 1) {
    const bucket = this.getBucket(clientId, role);

    if (bucket.tokens >= cost) {
      bucket.tokens -= cost;
      const remaining = Math.floor(bucket.tokens);
      const resetInSec = Math.ceil((bucket.capacity - bucket.tokens) / bucket.refillRatePerSec);

      return {
        allowed: true,
        remaining,
        limit: bucket.capacity,
        resetInSec
      };
    } else {
      const missingTokens = cost - bucket.tokens;
      const retryAfterSec = Math.ceil(missingTokens / bucket.refillRatePerSec);

      return {
        allowed: false,
        remaining: 0,
        limit: bucket.capacity,
        retryAfterSec,
        error: 'RATE_LIMIT_EXCEEDED'
      };
    }
  }

  _cleanupIdle() {
    const now = Date.now();
    for (const [clientId, bucket] of this.buckets.entries()) {
      // If idle for over 10 minutes and full, prune from memory
      if (now - bucket.lastRefillTimeMs > 600000 && bucket.tokens >= bucket.capacity) {
        this.buckets.delete(clientId);
      }
    }
  }

  destroy() {
    clearInterval(this.cleanupTimer);
  }
}

module.exports = TokenBucketRateLimiter;
