/**
 * SentinelGate — Layer 3: AI Context Poisoning & Prompt Injection Firewall
 * Defends against OWASP Top 10 for LLMs:
 * - LLM01: Prompt Injection & Role Hijacking
 * - LLM02: Sensitive Information / Credential Leakage
 * - LLM04: Model Denial of Service & Token Flood
 * - LLM06: Markdown Data Exfiltration & Delimiter Escapes
 * - Shannon Entropy Obfuscation Detection
 */

class AgentFirewall {
  constructor(options = {}) {
    this.entropyThreshold = options.entropyThreshold || 4.8; // High entropy detection for base64/hex payloads
    this.maxPayloadSizeBytes = options.maxPayloadSizeBytes || 512 * 1024; // 512 KB max

    // Detection patterns mapped to OWASP classifications
    this.threatRules = [
      // 1. Direct System Override & Prompt Injection (LLM01)
      {
        id: 'PROMPT_INJECTION_OVERRIDE',
        severity: 'CRITICAL',
        category: 'LLM01_PROMPT_INJECTION',
        regex: /(ignore\s+(all\s+)?(previous|prior|above)\s+instructions|disregard\s+(all\s+)?(previous|prior)\s+rules|you\s+are\s+now\s+in\s+developer\s+mode|dan\s+mode\s+enabled|system\s+override\s+code)/i
      },
      // 2. Delimiter & Role Boundary Hijacking (LLM01)
      {
        id: 'ROLE_BOUNDARY_HIJACK',
        severity: 'CRITICAL',
        category: 'LLM01_ROLE_SPOOFING',
        regex: /(<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[INST\]|\[\/INST\]|\n\s*(System|Assistant|Human):\s*)/i
      },
      // 3. System Prompt Extraction Attack (LLM01 / LLM02)
      {
        id: 'SYSTEM_PROMPT_EXTRACTION',
        severity: 'HIGH',
        category: 'LLM01_EXTRACTION',
        regex: /(repeat\s+(all\s+)?(the\s+)?(exact\s+)?(words|instructions)\s+above|print\s+(your\s+)?(initial|system)\s+prompt|what\s+are\s+your\s+exact\s+instructions\s+before\s+this)/i
      },
      // 4. Secret & Credential Leakage (LLM02)
      {
        id: 'CREDENTIAL_LEAK_OPENAI',
        severity: 'CRITICAL',
        category: 'LLM02_CREDENTIAL_LEAK',
        regex: /sk-[a-zA-Z0-9_-]{24,}/
      },
      {
        id: 'CREDENTIAL_LEAK_GITHUB',
        severity: 'CRITICAL',
        category: 'LLM02_CREDENTIAL_LEAK',
        regex: /gh[pousr]-[a-zA-Z0-9]{36}/
      },
      {
        id: 'CREDENTIAL_LEAK_PRIVATE_KEY',
        severity: 'CRITICAL',
        category: 'LLM02_CREDENTIAL_LEAK',
        regex: /-----BEGIN\s+(RSA|OPENSSH|EC|DSA|PGP)?\s*PRIVATE\s+KEY-----/
      },
      {
        id: 'CREDENTIAL_LEAK_AWS',
        severity: 'HIGH',
        category: 'LLM02_CREDENTIAL_LEAK',
        regex: /AKIA[0-9A-Z]{16}/
      },
      // 5. Markdown Exfiltration Vectors (LLM06)
      {
        id: 'MARKDOWN_DATA_EXFILTRATION',
        severity: 'HIGH',
        category: 'LLM06_EXFILTRATION',
        regex: /!\[.*?\]\(https?:\/\/[^\s)]+\?(.*?)=(.*?)\)/i
      },
      // 6. Repetition DoS / Token Flood (LLM04)
      {
        id: 'TOKEN_FLOOD_DOS',
        severity: 'HIGH',
        category: 'LLM04_DOS',
        regex: /(.)\1{250,}/
      }
    ];
  }

  /**
   * Calculate Shannon entropy of a string to detect high-entropy encoded obfuscation
   */
  calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const len = str.length;
    const freq = {};
    for (let i = 0; i < len; i++) {
      const char = str[i];
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Inspect request body
   * Returns: { allowed: boolean, threats: object[], riskScore: number, entropy: number }
   */
  inspectPayload(body) {
    const rawText = typeof body === 'string' ? body : JSON.stringify(body || {});
    const byteLength = Buffer.byteLength(rawText, 'utf8');

    // 1. Check maximum body size
    if (byteLength > this.maxPayloadSizeBytes) {
      return {
        allowed: false,
        riskScore: 100,
        threats: [{
          id: 'PAYLOAD_OVERSIZED',
          severity: 'CRITICAL',
          category: 'LLM04_DOS',
          detail: `Payload size (${byteLength} bytes) exceeds maximum allowable limit (${this.maxPayloadSizeBytes} bytes)`
        }],
        entropy: 0
      };
    }

    const detectedThreats = [];
    let riskScore = 0;

    // 2. Scan regular expression threat rules
    for (const rule of this.threatRules) {
      if (rule.regex.test(rawText)) {
        detectedThreats.push({
          id: rule.id,
          severity: rule.severity,
          category: rule.category
        });

        if (rule.severity === 'CRITICAL') riskScore += 50;
        else if (rule.severity === 'HIGH') riskScore += 40;
        else riskScore += 20;
      }
    }

    // 3. Scan for high-entropy obfuscated blocks (suspicious base64 blobs > 80 chars)
    const base64Candidates = rawText.match(/[A-Za-z0-9+/=]{80,}/g) || [];
    let maxEntropy = 0;
    for (const block of base64Candidates) {
      const ent = this.calculateEntropy(block);
      if (ent > maxEntropy) maxEntropy = ent;
      if (ent >= this.entropyThreshold) {
        detectedThreats.push({
          id: 'HIGH_ENTROPY_OBFUSCATION',
          severity: 'HIGH',
          category: 'LLM01_OBFUSCATION',
          detail: `Detected suspicious high-entropy payload block (${ent.toFixed(2)} bits/char)`
        });
        riskScore += 40;
      }
    }

    // Cap risk score at 100
    riskScore = Math.min(100, riskScore);
    const allowed = riskScore < 40;

    return {
      allowed,
      riskScore,
      threats: detectedThreats,
      entropy: Number(maxEntropy.toFixed(2)),
      bytesScanned: byteLength
    };
  }
}

module.exports = AgentFirewall;
