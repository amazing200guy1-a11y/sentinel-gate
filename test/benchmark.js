/**
 * SentinelGate — High-Concurrency Latency & Throughput Benchmark
 * Simulates 10,000 multi-tenant zero-trust API calls to measure overhead percentiles.
 */

const SentinelGate = require('../src/gateway');

console.log('\n=============================================================');
console.log('  SentinelGate — Zero-Trust Latency & Throughput Benchmark');
console.log('=============================================================\n');

const gate = new SentinelGate();
const TOTAL_REQUESTS = 10000;
const testApiKey = 'sg_live_alpha_99x821';
const testSecret = 'sec_alpha_hmac_secret_key_882';

// Set high capacity for benchmarking pure pipeline latency
gate.rateLimiter.tierConfigs.standard.capacity = 100000;
gate.rateLimiter.tierConfigs.standard.refillRatePerSec = 100000;

console.log(`Executing ${TOTAL_REQUESTS.toLocaleString()} full-pipeline zero-trust evaluations...`);
const startBenchmarkTime = process.hrtime.bigint();

const latencies = new Float64Array(TOTAL_REQUESTS);

for (let i = 0; i < TOTAL_REQUESTS; i++) {
  const reqStart = process.hrtime.bigint();
  const body = { query: 'fetch user profile data', index: i };
  const sig = gate.cryptoAuth.createSignature(testSecret, body);

  const res = gate.processRequest({
    apiKey: testApiKey,
    signatureHeader: sig,
    rawBody: body,
    toolCall: { name: 'search_docs', arguments: { query: 'getting started' } }
  });

  const reqEnd = process.hrtime.bigint();
  latencies[i] = Number(reqEnd - reqStart) / 1e6; // to milliseconds
}

const totalElapsedNs = process.hrtime.bigint() - startBenchmarkTime;
const totalElapsedSec = Number(totalElapsedNs) / 1e9;
const throughputRps = Math.round(TOTAL_REQUESTS / totalElapsedSec);

// Sort latencies to compute percentiles
latencies.sort();
const p50 = latencies[Math.floor(TOTAL_REQUESTS * 0.50)];
const p90 = latencies[Math.floor(TOTAL_REQUESTS * 0.90)];
const p95 = latencies[Math.floor(TOTAL_REQUESTS * 0.95)];
const p99 = latencies[Math.floor(TOTAL_REQUESTS * 0.99)];
const p999 = latencies[Math.floor(TOTAL_REQUESTS * 0.999)];
const max = latencies[TOTAL_REQUESTS - 1];

const mem = process.memoryUsage();

console.log('\n--- PERFORMANCE TELEMETRY ---');
console.log(`Throughput          : ${throughputRps.toLocaleString()} requests/sec`);
console.log(`Total Time Elapsed  : ${totalElapsedSec.toFixed(3)} seconds`);
console.log(`Median Latency (p50): ${p50.toFixed(3)} ms`);
console.log(`90th Percentile(p90): ${p90.toFixed(3)} ms`);
console.log(`95th Percentile(p95): ${p95.toFixed(3)} ms`);
console.log(`99th Percentile(p99): ${p99.toFixed(3)} ms`);
console.log(`99.9th Percentile   : ${p999.toFixed(3)} ms`);
console.log(`Max Latency         : ${max.toFixed(3)} ms`);
console.log('\n--- SYSTEM FOOTPRINT ---');
console.log(`Heap Used           : ${(mem.heapUsed / 1024 / 1024).toFixed(2)} MB`);
console.log(`Resident Set (RSS)  : ${(mem.rss / 1024 / 1024).toFixed(2)} MB`);
console.log(`Ledger Integrity    : ${gate.auditLedger.verifyChainIntegrity().intact ? 'INTACT (100% Tamper-Evident)' : 'CORRUPTED'}`);
console.log('=============================================================\n');
