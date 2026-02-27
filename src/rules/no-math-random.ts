import { Rule, Finding } from '../types';

/**
 * RULE: no-math-random
 * Detects Math.random() usage — use crypto.randomBytes/randomInt instead.
 */
export const noMathRandom: Rule = {
    id: 'no-math-random',
    name: 'No Math.random()',
    severity: 'HIGH',
    description: 'Math.random() is not cryptographically secure. Use crypto module for IDs, tokens, and entropy.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

            if (/Math\.random\s*\(/.test(line)) {
                findings.push({
                    ruleId: this.id,
                    ruleName: this.name,
                    severity: this.severity,
                    filePath,
                    line: i + 1,
                    message: 'Math.random() is not cryptographically secure.',
                    recommendation: 'Use crypto.randomBytes() or crypto.randomInt() for secure randomness.',
                });
            }
        }

        return findings;
    },
};
