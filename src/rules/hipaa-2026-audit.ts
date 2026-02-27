import { Rule, Finding } from '../types';

/**
 * RULE: hipaa-2026-audit
 * Enforces HIPAA-2026 compliance standards in medical documentation (NPP).
 * 
 * Standards:
 * 1. Revision Date >= 2026-02-16
 * 2. Inclusion of "Direct Electronic Access"
 * 3. Mention of "SAGA-AAP" for cryptographic protection
 */
export const hipaa2026Audit: Rule = {
    id: 'hipaa-2026-audit',
    name: 'HIPAA-2026 Compliance Audit',
    severity: 'CRITICAL',
    description: 'Verifies that medical documentation meets the 2026 regulatory finality standards.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const contentLower = content.toLowerCase();

        // 1. Revision Date Check
        const revisionMatch = content.match(/Revision (?:Date|Deadline):\s*([A-Za-z]+\s+\d{1,2},\s+\d{4})/i);
        if (revisionMatch) {
            const dateStr = revisionMatch[1];
            const revDate = new Date(dateStr);
            const deadline = new Date('2026-02-16');

            // Normalize to midnight UTC using local components to avoid timezone shifts
            const revTime = Date.UTC(revDate.getFullYear(), revDate.getMonth(), revDate.getDate());
            const deadlineTime = Date.UTC(2026, 1, 16);

            if (revTime < deadlineTime) {
                findings.push({
                    ruleId: this.id,
                    ruleName: this.name,
                    severity: 'CRITICAL',
                    filePath,
                    line: 1, // Summary line
                    message: `STALE REVISION: NPP Revision Date (${dateStr}) is before the HIPAA-2026 deadline (Feb 16, 2026).`,
                    recommendation: 'Update the Notice of Privacy Practices to reflect 2026 regulatory finality.',
                });
            }
        } else {
            findings.push({
                ruleId: this.id,
                ruleName: this.name,
                severity: 'HIGH',
                filePath,
                line: 1,
                message: 'MISSING REVISION DATE: No valid HIPAA revision date found.',
                recommendation: 'Explicitly state the "Revision Date" in the document header.',
            });
        }

        // 2. Direct Electronic Access
        if (!contentLower.includes('direct electronic access')) {
            findings.push({
                ruleId: this.id,
                ruleName: this.name,
                severity: 'CRITICAL',
                filePath,
                line: 5,
                message: 'AUTHORIZATION GAP: Missing "Direct Electronic Access" clause required by HIPAA-2026.',
                recommendation: 'Insert language guaranteeing patients direct electronic access to their PHI via SAGA-compliant APIs.',
            });
        }

        // 3. SAGA-AAP Mention
        if (!content.includes('SAGA-AAP')) {
            findings.push({
                ruleId: this.id,
                ruleName: this.name,
                severity: 'HIGH',
                filePath,
                line: 10,
                message: 'CRYPTOGRAPHIC VULNERABILITY: Document lacks SAGA-AAP token protection disclosure.',
                recommendation: 'Disclose the use of Agent Authorization Profiles (AAP-01) for securing patient records.',
            });
        }

        return findings;
    },
};
