import { Rule, Finding } from '../types';

/**
 * RULE: no-console-log
 * Detects console.log statements in production code.
 * console.error and console.warn are allowed.
 */
export const noConsoleLog: Rule = {
    id: 'no-console-log',
    name: 'No Console.log in Production',
    severity: 'LOW',
    description: 'Remove console.log statements from production code. Use a structured logger.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            // Skip comments
            if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

            if (/console\.log\s*\(/.test(line)) {
                findings.push({
                    ruleId: this.id,
                    ruleName: this.name,
                    severity: this.severity,
                    filePath,
                    line: i + 1,
                    message: 'console.log found in production code.',
                    recommendation: 'Replace with a structured logger or remove before shipping.',
                });
            }
        }

        return findings;
    },
};
