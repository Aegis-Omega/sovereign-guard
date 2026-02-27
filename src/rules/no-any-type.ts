import { Rule, Finding } from '../types';

/**
 * RULE: no-any-type
 * Detects usage of the `any` type which bypasses TypeScript's type system.
 */
export const noAnyType: Rule = {
    id: 'no-any-type',
    name: 'No Any Type',
    severity: 'MEDIUM',
    description: 'Avoid using `any` — it disables type safety and hides bugs.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            // Skip comments
            if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

            // Match type annotations with `any` — `: any`, `<any>`, `as any`
            const patterns = [
                /:\s*any\b/,
                /<any>/,
                /as\s+any\b/,
                /:\s*any\s*[,)}\]]/,
            ];

            for (const pattern of patterns) {
                if (pattern.test(line)) {
                    findings.push({
                        ruleId: this.id,
                        ruleName: this.name,
                        severity: this.severity,
                        filePath,
                        line: i + 1,
                        message: `Unsafe \`any\` type detected: ${line.trim().slice(0, 80)}`,
                        recommendation: 'Use a specific type, generic, or `unknown` with type narrowing.',
                    });
                    break; // One finding per line
                }
            }
        }

        return findings;
    },
};
