import { Rule, Finding } from '../types';

/**
 * RULE: missing-audit-trail
 * Detects modules with no logging or telemetry instrumentation.
 */
export const missingAuditTrail: Rule = {
    id: 'missing-audit-trail',
    name: 'Missing Audit Trail',
    severity: 'MEDIUM',
    description: 'Production modules should have logging for observability and debugging.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lines = content.split('\n');

        // Skip test files, config files, and type-only files
        if (filePath.includes('.test.') || filePath.includes('.spec.') ||
            filePath.includes('.d.ts') || filePath.includes('types')) {
            return findings;
        }

        // Check for any form of logging or telemetry
        const hasLogging = /console\.(log|error|warn|info)\s*\(/.test(content);
        const hasTelemetry = /logger|telemetry|trace|recordEvent|analytics|monitor/.test(content);

        // Only flag modules with actual logic (>15 lines, has functions)
        const hasLogic = lines.length > 15 && /(?:function|=>|class)\s/.test(content);

        if (!hasLogging && !hasTelemetry && hasLogic) {
            findings.push({
                ruleId: this.id,
                ruleName: this.name,
                severity: this.severity,
                filePath,
                line: 1,
                message: 'Module has no logging or telemetry instrumentation.',
                recommendation: 'Add structured logging for observability in production.',
            });
        }

        return findings;
    },
};
