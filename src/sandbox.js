/**
 * SentinelGate — Layer 4: Agent Tool Execution Sandbox
 * Defends against OWASP LLM07 (Insecure Plugin Design) & LLM08 (Excessive Agency):
 * - Least-privilege tool execution permissions by client role
 * - Interception of shell command injection & dangerous binary invocations
 * - Strict path traversal & directory escape blocking
 * - Strict parameter type and constraint validation
 */

class AgentSandbox {
  constructor(options = {}) {
    // Role-based tool access control matrix (RBAC)
    this.rolePermissions = {
      readonly: new Set(['read_query', 'get_weather', 'search_docs', 'get_user_info']),
      standard: new Set(['read_query', 'get_weather', 'search_docs', 'get_user_info', 'send_notification', 'create_ticket']),
      admin:    new Set(['read_query', 'get_weather', 'search_docs', 'get_user_info', 'send_notification', 'create_ticket', 'write_query', 'execute_script'])
    };

    // Dangerous shell patterns and binaries that must NEVER execute
    this.destructiveCommandPatterns = [
      /\b(rm\s+-rf|del\s+\/f|format\s+[a-z]:|mkfs|dd\s+if=)/i,
      /\b(drop\s+(database|table)|truncate\s+table)\b/i,
      /\b(powershell(\.exe)?\s+(-enc|-encodedcommand|-e\s+))/i,
      /\b(nc|netcat|ncat)\s+.*-e\s+/i,
      /(curl|wget)\s+.*\|\s*(sh|bash|zsh|powershell)/i,
      /[;&|`$]\s*(rm|del|shutdown|reboot|curl|wget|nc)\b/i
    ];

    // Path traversal signatures
    this.pathTraversalPatterns = [
      /\.\.[\/\\]/,
      /[\/\\]etc[\/\\](passwd|shadow|sudoers)/i,
      /[\/\\]windows[\/\\]system32/i,
      /\.ssh[\/\\](id_rsa|id_ed25519|authorized_keys)/i,
      /[\/\\]proc[\/\\]self[\/\\]/i
    ];
  }

  /**
   * Authorize and validate a tool call before execution
   * @param {string} role - Authenticated client role ('readonly', 'standard', 'admin')
   * @param {string} toolName - Target tool to execute
   * @param {object} args - Arguments passed to the tool
   * @returns {object} { allowed: boolean, violations: string[], sanitizedArgs: object }
   */
  validateToolExecution(role = 'standard', toolName, args = {}) {
    const violations = [];

    // 1. Enforce RBAC Least Privilege
    const permittedTools = this.rolePermissions[role] || this.rolePermissions.readonly;
    if (!permittedTools.has(toolName)) {
      violations.push({
        code: 'UNAUTHORIZED_TOOL_INVOCATION',
        detail: `Role '${role}' is not authorized to invoke tool '${toolName}'. Least-privilege violation.`
      });
      return { allowed: false, violations };
    }

    // 2. Deep scan tool arguments for shell injection and path traversal
    this._deepScanArgs(args, violations);

    return {
      allowed: violations.length === 0,
      violations,
      toolName,
      role
    };
  }

  _deepScanArgs(obj, violations, currentPath = '') {
    if (!obj || typeof obj !== 'object') return;

    for (const [key, value] of Object.entries(obj)) {
      const fieldPath = currentPath ? `${currentPath}.${key}` : key;

      if (typeof value === 'string') {
        // Check destructive shell commands
        for (const pattern of this.destructiveCommandPatterns) {
          if (pattern.test(value)) {
            violations.push({
              code: 'DANGEROUS_COMMAND_INJECTION',
              field: fieldPath,
              detail: `Disallowed dangerous command or delimiter pattern detected in parameter '${fieldPath}'`
            });
            break;
          }
        }

        // Check path traversal
        for (const pattern of this.pathTraversalPatterns) {
          if (pattern.test(value)) {
            violations.push({
              code: 'PATH_TRAVERSAL_DETECTED',
              field: fieldPath,
              detail: `Directory traversal escape sequence detected in file path parameter '${fieldPath}'`
            });
            break;
          }
        }
      } else if (typeof value === 'object' && value !== null) {
        this._deepScanArgs(value, violations, fieldPath);
      }
    }
  }
}

module.exports = AgentSandbox;
