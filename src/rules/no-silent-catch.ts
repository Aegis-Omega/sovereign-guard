import { Rule, Finding } from '../types';

/**
 * RULE: no-silent-catch
 * Detects empty catch blocks or catch blocks with only comments.
 * Silent error swallowing hides bugs and makes debugging impossible.
 */
export const noSilentCatch: Rule = {
    id: 'no-silent-catch',
    name: 'No Silent Catch Blocks',
    severity: 'HIGH',
    description: 'Catch blocks must handle errors explicitly, not swallow them silently.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();

            // Match: catch { } or catch (e) { }
            if (line.match(/catch\s*(\([^)]*\))?\s*\{/)) {
                // Look ahead for empty body or comment-only body
                let braceDepth = 0;
                let isEmpty = true;
                let started = false;

                for (let j = i; j < Math.min(i + 10, lines.length); j++) {
                    const checkLine = lines[j];
                    for (const ch of checkLine) {
                        if (ch === '{') { braceDepth++; started = true; }
                        if (ch === '}') braceDepth--;
                    }

                    // Check if line has actual code (not just braces, whitespace, comments)
                    const stripped = checkLine.trim()
                        .replace(/^catch\s*(\([^)]*\))?\s*\{?\s*/, '')
                        .replace(/[{}]/g, '')
                        .replace(/\/\/.*$/, '')
                        .replace(/\/\*.*?\*\//g, '')
                        .trim();

                    if (stripped.length > 0) {
                        isEmpty = false;
                    }

                    if (started && braceDepth === 0) break;
                }

                if (isEmpty) {
                    findings.push({
                        ruleId: this.id,
                        ruleName: this.name,
                        severity: this.severity,
                        filePath,
                        line: i + 1,
                        message: 'Empty catch block silently swallows errors.',
                        recommendation: 'Add error logging: console.error("Context:", err)',
                    });
                }
            }
        }

        return findings;
    },
};
