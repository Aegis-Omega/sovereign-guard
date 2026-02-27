import { Rule, Finding } from '../types';

/**
 * RULE: missing-error-handling
 * Detects async functions without any try/catch error handling.
 */
export const missingErrorHandling: Rule = {
    id: 'missing-error-handling',
    name: 'Missing Error Handling',
    severity: 'HIGH',
    description: 'Async functions should have error handling to prevent unhandled rejections.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lines = content.split('\n');

        // Find async functions and check for try/catch within their scope
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (/async\s+(?:function\s+\w+|[\w.]+\s*=\s*async|\w+\s*\()/.test(line) ||
                /async\s*\(/.test(line)) {

                // Scan forward to find matching braces and check for try/catch
                let braceDepth = 0;
                let started = false;
                let hasTryCatch = false;
                let hasCatch = false;

                for (let j = i; j < Math.min(i + 100, lines.length); j++) {
                    const checkLine = lines[j];
                    for (const ch of checkLine) {
                        if (ch === '{') { braceDepth++; started = true; }
                        if (ch === '}') braceDepth--;
                    }

                    if (/\btry\s*\{/.test(checkLine)) hasTryCatch = true;
                    if (/\.catch\s*\(/.test(checkLine)) hasCatch = true;

                    if (started && braceDepth === 0) break;
                }

                if (!hasTryCatch && !hasCatch && started) {
                    // Extract function name
                    const nameMatch = line.match(/(?:async\s+function\s+(\w+)|(\w+)\s*(?:=|:)\s*async|async\s+(\w+))/);
                    const funcName = nameMatch?.[1] || nameMatch?.[2] || nameMatch?.[3] || 'anonymous';

                    findings.push({
                        ruleId: this.id,
                        ruleName: this.name,
                        severity: this.severity,
                        filePath,
                        line: i + 1,
                        message: `Async function '${funcName}' has no error handling.`,
                        recommendation: 'Wrap body in try/catch or add .catch() to the promise chain.',
                    });
                }
            }
        }

        return findings;
    },
};
