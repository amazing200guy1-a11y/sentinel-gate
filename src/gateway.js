/**
 * SentinelGate — Unified Zero-Trust AI Security Gateway
 * Coordinates all 5 defense layers into a sub-millisecond pipeline:
 * 1. Cryptographic Ingress Verification (HMAC-SHA256 & API Key Timing-Safe Equal)
 * 2. Token-Bucket Rate Limiter (<0.1ms sliding window)
 * 3. AI Context Poisoning & Prompt Injection Firewall (OWASP Top 10 for LLMs)
 * 4. Agent Tool Execution Sandbox (Least privilege & command injection blocker)
 * 5. Tamper-Evident SHA-256 Chained Audit Ledger
 *
 * Live telemetry streamed via Server-Sent Events on GET /v1/events
 */

const http = require('http');
const crypto = require('crypto');
const CryptoAuth = require('./crypto_auth');
const TokenBucketRateLimiter = require('./rate_limiter');
const AgentFirewall = require('./firewall');
const AgentSandbox = require('./sandbox');
const AuditLedger = require('./audit_logger');

class SentinelGate {
  constructor(options = {}) {
    this.cryptoAuth = new CryptoAuth(options.auth);
    this.rateLimiter = new TokenBucketRateLimiter(options.rateLimit);
    this.firewall = new AgentFirewall(options.firewall);
    this.sandbox = new AgentSandbox(options.sandbox);
    this.auditLedger = new AuditLedger(options.audit);

    // SSE subscriber list — each entry is a live response stream
    this._sseClients = new Set();

    // Register default demo keys for testing and benchmarks
    this.cryptoAuth.registerClient('agent-alpha',    'sg_live_alpha_99x821',    'sec_alpha_hmac_secret_key_882',    'standard');
    this.cryptoAuth.registerClient('agent-admin',    'sg_live_admin_44z991',    'sec_admin_hmac_secret_key_771',    'admin');
    this.cryptoAuth.registerClient('agent-readonly', 'sg_live_readonly_11a332', 'sec_readonly_hmac_secret_key_552', 'readonly');
  }

  // ─── SSE broadcast ────────────────────────────────────────────────────────
  _broadcast(eventName, data) {
    const payload = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of this._sseClients) {
      try { client.write(payload); } catch (_) { this._sseClients.delete(client); }
    }
  }

  /**
   * Execute the full 5-layer Zero-Trust inspection pipeline
   */
  processRequest({ apiKey, signatureHeader, rawBody, toolCall = null, endpoint = '/v1/gateway/inspect' }) {
    const startTime = process.hrtime.bigint();
    const requestId = 'req_' + crypto.randomBytes(8).toString('hex');

    // ──────────────── Layer 1: Cryptographic Authentication ────────────────
    const authResult = this.cryptoAuth.authenticateApiKey(apiKey);
    if (!authResult.authenticated) {
      const latencyMs = Number(process.hrtime.bigint() - startTime) / 1e6;
      this.auditLedger.logEvent({ requestId, endpoint, allowed: false, threats: [{ id: authResult.error }], latencyMs });
      const result = { allowed: false, statusCode: 401, error: authResult.error, requestId, latencyMs, blockedLayer: 1 };
      this._broadcast('decision', result);
      return result;
    }

    const client = authResult.client;

    // Verify HMAC Signature
    if (signatureHeader) {
      const sigResult = this.cryptoAuth.verifyRequestSignature(client.secretKey, rawBody, signatureHeader);
      if (!sigResult.verified) {
        const latencyMs = Number(process.hrtime.bigint() - startTime) / 1e6;
        this.auditLedger.logEvent({ requestId, clientId: client.clientId, role: client.role, endpoint, allowed: false, threats: [{ id: sigResult.error }], latencyMs });
        const result = { allowed: false, statusCode: 403, error: sigResult.error, requestId, latencyMs, blockedLayer: 1 };
        this._broadcast('decision', result);
        return result;
      }
    }

    // ──────────────── Layer 2: Token-Bucket Rate Limiter ────────────────
    const rateCheck = this.rateLimiter.consume(client.clientId, client.role);
    if (!rateCheck.allowed) {
      const latencyMs = Number(process.hrtime.bigint() - startTime) / 1e6;
      this.auditLedger.logEvent({ requestId, clientId: client.clientId, role: client.role, endpoint, allowed: false, threats: [{ id: 'RATE_LIMIT_EXCEEDED' }], latencyMs });
      const result = { allowed: false, statusCode: 429, error: 'RATE_LIMIT_EXCEEDED', retryAfterSec: rateCheck.retryAfterSec, requestId, latencyMs, blockedLayer: 2 };
      this._broadcast('decision', result);
      return result;
    }

    // ──────────────── Layer 3: AI Context Poisoning & Prompt Firewall ────────────────
    const firewallResult = this.firewall.inspectPayload(rawBody);
    if (!firewallResult.allowed) {
      const latencyMs = Number(process.hrtime.bigint() - startTime) / 1e6;
      this.auditLedger.logEvent({ requestId, clientId: client.clientId, role: client.role, endpoint, allowed: false, threats: firewallResult.threats, latencyMs });
      const result = { allowed: false, statusCode: 400, error: 'FIREWALL_BLOCKED_ATTACK', riskScore: firewallResult.riskScore, threats: firewallResult.threats, requestId, latencyMs, blockedLayer: 3 };
      this._broadcast('decision', result);
      return result;
    }

    // ──────────────── Layer 4: Agent Tool Execution Sandbox ────────────────
    let sandboxResult = { allowed: true, violations: [] };
    if (toolCall) {
      sandboxResult = this.sandbox.validateToolExecution(client.role, toolCall.name, toolCall.arguments || {});
      if (!sandboxResult.allowed) {
        const latencyMs = Number(process.hrtime.bigint() - startTime) / 1e6;
        this.auditLedger.logEvent({ requestId, clientId: client.clientId, role: client.role, endpoint, allowed: false, violations: sandboxResult.violations, latencyMs });
        const result = { allowed: false, statusCode: 403, error: 'SANDBOX_VIOLATION', violations: sandboxResult.violations, requestId, latencyMs, blockedLayer: 4 };
        this._broadcast('decision', result);
        return result;
      }
    }

    // ──────────────── Layer 5: Tamper-Evident Chained Audit Logging ────────────────
    const latencyMs = Number(process.hrtime.bigint() - startTime) / 1e6;
    const auditRecord = this.auditLedger.logEvent({ requestId, clientId: client.clientId, role: client.role, endpoint, allowed: true, threats: firewallResult.threats, latencyMs });

    const result = {
      allowed: true,
      statusCode: 200,
      requestId,
      latencyMs,
      riskScore: firewallResult.riskScore,
      auditHash: auditRecord.hash,
      rateLimit: { remaining: rateCheck.remaining, limit: rateCheck.limit, resetInSec: rateCheck.resetInSec }
    };
    this._broadcast('decision', result);
    return result;
  }

  /**
   * Start standalone HTTP Gateway daemon with SSE live feed
   */
  startServer(port = 8443) {
    this.server = http.createServer(async (req, res) => {
      const url = req.url;
      const method = req.method;

      // CORS — allow dashboard.html (GitHub Pages or local) to connect
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, X-Signature');

      if (method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

      // ── GET /v1/events  ── Server-Sent Events live feed ──────────────────
      if (url === '/v1/events' && method === 'GET') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'X-Accel-Buffering': 'no'
        });
        // Send initial snapshot
        res.write(`event: snapshot\ndata: ${JSON.stringify(this.auditLedger.getTelemetry())}\n\n`);
        this._sseClients.add(res);
        req.on('close', () => this._sseClients.delete(res));
        // Keep-alive ping every 25s
        const ping = setInterval(() => {
          try { res.write(': ping\n\n'); } catch (_) { clearInterval(ping); this._sseClients.delete(res); }
        }, 25000);
        return;
      }

      // ── GET /health ──────────────────────────────────────────────────────
      if (url === '/health' && method === 'GET') {
        const telemetry = this.auditLedger.getTelemetry();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'OPERATIONAL',
          ledger_integrity: this.auditLedger.verifyChain(),
          uptime_seconds: Math.floor(process.uptime()),
          telemetry,
          timestamp: new Date().toISOString()
        }));
        return;
      }

      // ── GET /v1/telemetry ────────────────────────────────────────────────
      if (url === '/v1/telemetry' && method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(this.auditLedger.getTelemetry(), null, 2));
        return;
      }

      // ── GET /v1/audit/chain ──────────────────────────────────────────────
      if (url === '/v1/audit/chain' && method === 'GET') {
        const chain = this.auditLedger.getChain ? this.auditLedger.getChain() : [];
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ intact: this.auditLedger.verifyChain(), entries: chain }, null, 2));
        return;
      }

      // ── POST /v1/gateway/inspect ─────────────────────────────────────────
      if (url === '/v1/gateway/inspect' && method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          let parsed = {};
          try { parsed = JSON.parse(body); } catch(e) { parsed = body; }

          const apiKey = req.headers['x-api-key'] || (typeof parsed === 'object' ? parsed.apiKey : null);
          const sig    = req.headers['x-signature'];

          const result = this.processRequest({
            apiKey,
            signatureHeader: sig,
            rawBody: typeof parsed === 'object' && parsed.payload !== undefined ? parsed.payload : parsed,
            toolCall: typeof parsed === 'object' ? parsed.toolCall : null
          });

          res.writeHead(result.statusCode, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        });
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'NOT_FOUND', path: url }));
    });

    return new Promise(resolve => {
      this.server.listen(port, () => {
        console.log(`[SentinelGate] Zero-Trust AI Security Gateway online → http://127.0.0.1:${port}`);
        console.log(`[SentinelGate] Live SSE feed              → http://127.0.0.1:${port}/v1/events`);
        console.log(`[SentinelGate] Health check               → http://127.0.0.1:${port}/health`);
        resolve(this.server);
      });
    });
  }

  stopServer() {
    if (this.server) this.server.close();
    this.cryptoAuth.destroy();
    this.rateLimiter.destroy();
  }
}

// Auto-run daemon if invoked directly
if (require.main === module) {
  const gate = new SentinelGate();
  const PORT = process.env.PORT || 8443;
  gate.startServer(PORT).then(() => {
    console.log(`[SentinelGate] Dashboard: open dashboard.html in browser and connect to http://127.0.0.1:${PORT}`);
  });
}

module.exports = SentinelGate;
