import { Rule, Finding } from '../types';

/**
 * RULE: no-agent-auth-profile
 * Detects entropic identity management where agents act without structured 
 * Agent Authorization Profile (AAP) claims.
 * 
 * Enforces Era 50 Pillar 1: Verified Permission.
 */
export const noAgentAuthProfile: Rule = {
    id: 'no-agent-auth-profile',
    name: 'No Agent Authorization Profile',
    severity: 'CRITICAL',
    description: 'Agents must act with structured AAP claims (aap_task, aap_agent) to ensure mission binding.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lines = content.split('\n');

        // Target identity-handling files or transaction logic
        // Using word boundaries to avoid false positives (e.g. "Abstraction" containing "ACT")
        const identityKeywords = [/\bACT\b/, /\baid\b/, /\bSagaIdentity\b/, /\bAgentToken\b/, /\bauthorizeAgent\b/];
        const aapClaims = ['aap_task', 'aap_agent', 'task_id', 'purpose'];

        // If the file doesn't seem to handle identity, skip for performance
        if (!identityKeywords.some(regex => regex.test(content))) return findings;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];

            // Skip comments and imports
            if (line.trim().startsWith('//') || line.trim().startsWith('*') || line.trim().startsWith('import')) continue;

            const hasIdentity = identityKeywords.some(regex => regex.test(line));
            const hasAAP = aapClaims.some(k => line.includes(k));

            if (hasIdentity && !hasAAP) {
                findings.push({
                    ruleId: this.id,
                    ruleName: this.name,
                    severity: this.severity,
                    filePath,
                    line: i + 1,
                    message: 'Entropic agent action detected: Identity used without AAP mission binding.',
                    recommendation: 'Wrap agent calls in an AAP context including aap_task and aap_agent claims.',
                });
            }
        }

        return findings;
    },
};
