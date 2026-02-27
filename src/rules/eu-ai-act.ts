import { Rule, Finding } from '../types';

/**
 * RULE: eu-ai-act
 * EU AI Act (Regulation 2024/1689) — Title III High-Risk AI Systems
 *
 * Audits codebases and documentation for AI Act compliance:
 * 1. High-Risk AI Transparency (Art. 13)
 * 2. Human Oversight Mechanisms (Art. 14)
 * 3. Data Governance Documentation (Art. 10)
 * 4. Conformity Assessment References (Art. 43)
 */
export const euAiAct: Rule = {
    id: 'eu-ai-act',
    name: 'EU AI Act Compliance Audit',
    severity: 'CRITICAL',
    description: 'Verifies compliance with EU AI Act (2024/1689) requirements for high-risk AI systems.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lower = content.toLowerCase();

        // 1. Transparency (Art. 13)
        const hasTransparency =
            lower.includes('ai transparency') ||
            lower.includes('model transparency') ||
            lower.includes('explainability') ||
            lower.includes('interpretab') ||
            lower.includes('ai act');

        if (!hasTransparency) {
            findings.push({
                ruleId: this.id,
                ruleName: this.name,
                severity: 'CRITICAL',
                filePath,
                line: 1,
                message: 'EU AI ACT ART. 13: No AI transparency documentation found. High-risk AI systems must provide sufficient transparency for users to interpret output.',
                recommendation: 'Document AI system transparency measures including input/output specifications, performance metrics, and known limitations per EU AI Act Art. 13.',
            });
        }

        // 2. Human Oversight (Art. 14)
        const hasHumanOversight =
            lower.includes('human oversight') ||
            lower.includes('human-in-the-loop') ||
            lower.includes('human in the loop') ||
            lower.includes('human review') ||
            lower.includes('manual override');

        if (!hasHumanOversight) {
            findings.push({
                ruleId: this.id,
                ruleName: this.name,
                severity: 'CRITICAL',
                filePath,
                line: 1,
                message: 'EU AI ACT ART. 14: No human oversight mechanism detected. High-risk AI systems must be designed for effective human oversight.',
                recommendation: 'Implement human oversight controls including ability to override, interrupt, or shut down AI system per EU AI Act Art. 14.',
            });
        }

        // 3. Data Governance (Art. 10)
        const hasDataGovernance =
            lower.includes('data governance') ||
            lower.includes('training data') ||
            lower.includes('data quality') ||
            lower.includes('data bias') ||
            lower.includes('dataset');

        if (!hasDataGovernance) {
            findings.push({
                ruleId: this.id,
                ruleName: this.name,
                severity: 'HIGH',
                filePath,
                line: 1,
                message: 'EU AI ACT ART. 10: No data governance documentation found. Training, validation, and testing datasets must meet quality criteria.',
                recommendation: 'Document data governance practices including dataset provenance, bias assessment, and quality metrics per EU AI Act Art. 10.',
            });
        }

        // 4. Conformity Assessment (Art. 43)
        const hasConformity =
            lower.includes('conformity assessment') ||
            lower.includes('ce marking') ||
            lower.includes('notified body') ||
            lower.includes('eu declaration') ||
            lower.includes('certification');

        if (!hasConformity) {
            findings.push({
                ruleId: this.id,
                ruleName: this.name,
                severity: 'MEDIUM',
                filePath,
                line: 1,
                message: 'EU AI ACT ART. 43: No conformity assessment reference found. High-risk AI systems must undergo conformity assessment before market placement.',
                recommendation: 'Reference the applicable conformity assessment procedure and CE marking requirements per EU AI Act Art. 43.',
            });
        }

        return findings;
    },
};
