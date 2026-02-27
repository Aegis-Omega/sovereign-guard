import { Rule, Finding } from '../types';

/**
 * RULE: unused-imports
 * Detects imported symbols that are never referenced in the file body.
 */
export const unusedImports: Rule = {
    id: 'unused-imports',
    name: 'Unused Imports',
    severity: 'LOW',
    description: 'Unused imports increase bundle size and reduce code clarity.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();

            // Match named imports: import { Foo, Bar } from '...'
            const namedMatch = line.match(/^import\s*\{([^}]+)\}\s*from/);
            if (namedMatch) {
                const imports = namedMatch[1].split(',').map(s => s.trim().split(/\s+as\s+/).pop()!.trim());
                const bodyAfterImports = lines.slice(i + 1).join('\n');

                for (const sym of imports) {
                    if (!sym) continue;
                    // Check if symbol appears in the rest of the file (not in import lines)
                    const regex = new RegExp(`\\b${sym.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
                    if (!regex.test(bodyAfterImports)) {
                        findings.push({
                            ruleId: this.id,
                            ruleName: this.name,
                            severity: this.severity,
                            filePath,
                            line: i + 1,
                            message: `Imported symbol '${sym}' is never used.`,
                            recommendation: `Remove unused import: ${sym}`,
                        });
                    }
                }
            }
        }

        return findings;
    },
};
