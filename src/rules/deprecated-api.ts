import { Rule, Finding } from '../types';

/**
 * RULE: deprecated-api
 * Detects usage of deprecated JavaScript/TypeScript APIs.
 */
export const deprecatedApi: Rule = {
    id: 'deprecated-api',
    name: 'Deprecated API Usage',
    severity: 'MEDIUM',
    description: 'Deprecated APIs may be removed in future versions and should be replaced.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lines = content.split('\n');

        const deprecated = [
            { pattern: /\.substr\s*\(/, replacement: '.substring() or .slice()', api: 'String.substr()' },
            { pattern: /\.__proto__\b/, replacement: 'Object.getPrototypeOf()', api: '__proto__' },
            { pattern: /arguments\.callee\b/, replacement: 'named function reference', api: 'arguments.callee' },
            { pattern: /document\.write\s*\(/, replacement: 'DOM manipulation methods', api: 'document.write()' },
            { pattern: /new Buffer\s*\(/, replacement: 'Buffer.from() or Buffer.alloc()', api: 'new Buffer()' },
            { pattern: /\.trimLeft\s*\(/, replacement: '.trimStart()', api: 'String.trimLeft()' },
            { pattern: /\.trimRight\s*\(/, replacement: '.trimEnd()', api: 'String.trimRight()' },
            { pattern: /escape\s*\(/, replacement: 'encodeURIComponent()', api: 'escape()' },
            { pattern: /unescape\s*\(/, replacement: 'decodeURIComponent()', api: 'unescape()' },
        ];

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

            for (const { pattern, replacement, api } of deprecated) {
                if (pattern.test(line)) {
                    findings.push({
                        ruleId: this.id,
                        ruleName: this.name,
                        severity: this.severity,
                        filePath,
                        line: i + 1,
                        message: `Deprecated API: ${api}`,
                        recommendation: `Replace with: ${replacement}`,
                    });
                    break;
                }
            }
        }

        return findings;
    },
};
