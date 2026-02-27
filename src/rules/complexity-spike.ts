import { Rule, Finding } from '../types';

/**
 * RULE: complexity-spike
 * Detects files exceeding 200 lines and functions exceeding 50 lines.
 */
export const complexitySpike: Rule = {
    id: 'complexity-spike',
    name: 'Complexity Spike',
    severity: 'LOW',
    description: 'Large files and functions are harder to maintain and test.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lines = content.split('\n');

        // File-level check
        if (lines.length > 200) {
            findings.push({
                ruleId: this.id,
                ruleName: this.name,
                severity: this.severity,
                filePath,
                line: 1,
                message: `File has ${lines.length} lines (threshold: 200). Consider decomposing.`,
                recommendation: 'Split into smaller, focused modules with single responsibilities.',
            });
        }

        // Function-level check — detect long functions
        let funcStart = -1;
        let funcName = '';
        let braceDepth = 0;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const funcMatch = line.match(/(?:function\s+(\w+)|(\w+)\s*(?:=|:)\s*(?:async\s*)?\(|(?:async\s+)?(\w+)\s*\()/);

            if (funcMatch && /\{/.test(line) && funcStart === -1) {
                funcStart = i;
                funcName = funcMatch[1] || funcMatch[2] || funcMatch[3] || 'anonymous';
                braceDepth = 0;
            }

            if (funcStart >= 0) {
                for (const ch of line) {
                    if (ch === '{') braceDepth++;
                    if (ch === '}') braceDepth--;
                }

                if (braceDepth === 0 && funcStart >= 0) {
                    const funcLength = i - funcStart + 1;
                    if (funcLength > 50) {
                        findings.push({
                            ruleId: this.id,
                            ruleName: this.name,
                            severity: 'MEDIUM' as const,
                            filePath,
                            line: funcStart + 1,
                            message: `Function '${funcName}' is ${funcLength} lines (threshold: 50).`,
                            recommendation: 'Extract helper functions to reduce complexity.',
                        });
                    }
                    funcStart = -1;
                }
            }
        }

        return findings;
    },
};
