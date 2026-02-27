import { Rule, Finding } from '../types';

/**
 * RULE: todo-debt
 * Detects TODO, FIXME, HACK, and XXX comments — technical debt markers.
 */
export const todoDebt: Rule = {
    id: 'todo-debt',
    name: 'Technical Debt Markers',
    severity: 'LOW',
    description: 'TODO/FIXME/HACK comments represent unresolved technical debt.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lines = content.split('\n');
        const markers = /\b(TODO|FIXME|HACK|XXX)\b/;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const match = line.match(markers);
            if (match) {
                findings.push({
                    ruleId: this.id,
                    ruleName: this.name,
                    severity: this.severity,
                    filePath,
                    line: i + 1,
                    message: `${match[1]} comment: ${line.trim().slice(0, 80)}`,
                    recommendation: 'Resolve or create a tracked issue for this debt.',
                });
            }
        }

        return findings;
    },
};
