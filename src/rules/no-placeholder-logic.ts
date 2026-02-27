import { Rule, Finding } from '../types';

/**
 * RULE: no-placeholder-logic
 * Detects placeholder comments indicating unfinished implementations.
 */
export const noPlaceholderLogic: Rule = {
    id: 'no-placeholder-logic',
    name: 'No Placeholder Logic',
    severity: 'MEDIUM',
    description: 'Placeholder logic should be replaced with real implementations before shipping.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lines = content.split('\n');
        const markers = ['// [PLACEHOLDER]', '// PLACEHOLDER', '// STUB', '// MOCK'];

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            for (const marker of markers) {
                if (line.includes(marker)) {
                    findings.push({
                        ruleId: this.id,
                        ruleName: this.name,
                        severity: this.severity,
                        filePath,
                        line: i + 1,
                        message: `Placeholder logic detected: ${line.trim().slice(0, 80)}`,
                        recommendation: 'Replace with real implementation or remove before release.',
                    });
                    break;
                }
            }
        }

        return findings;
    },
};
