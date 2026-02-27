import { Rule, Finding } from '../types';

/**
 * RULE: dora-ict-risk
 * Digital Operational Resilience Act (DORA) — EU Regulation 2022/2554
 *
 * Audits codebases and documentation for ICT risk management compliance:
 * 1. ICT Risk Management Framework (Articles 5-16)
 * 2. Third-Party Provider Risk Disclosure (Articles 28-44)
 * 3. Incident Reporting Protocols (Articles 17-23)
 * 4. Resilience Testing Evidence (Articles 24-27)
 */
export const doraIctRisk: Rule = {
    id: 'dora-ict-risk',
    name: 'DORA ICT Risk Management Audit',
    severity: 'CRITICAL',
    description: 'Verifies compliance with EU DORA (2022/2554) ICT risk management and operational resilience requirements.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lower = content.toLowerCase();

        // 1. ICT Risk Management Framework (Art. 5-16)
        const hasRiskFramework =
            lower.includes('ict risk') ||
            lower.includes('risk management framework') ||
            lower.includes('operational resilience') ||
            lower.includes('dora');

        if (!hasRiskFramework) {
            findings.push({
                ruleId: this.id,
                ruleName: this.name,
                severity: 'CRITICAL',
                filePath,
                line: 1,
                message: 'DORA ART. 5-16: No ICT risk management framework detected. EU financial entities must maintain documented ICT risk governance.',
                recommendation: 'Implement and reference an ICT Risk Management Framework per DORA Articles 5-16. Document risk identification, protection, detection, response, and recovery procedures.',
            });
        }

        // 2. Third-Party Provider Risk (Art. 28-44)
        const hasThirdPartyRisk =
            lower.includes('third-party') ||
            lower.includes('third party') ||
            lower.includes('vendor risk') ||
            lower.includes('supply chain') ||
            lower.includes('outsourcing');

        if (!hasThirdPartyRisk) {
            findings.push({
                ruleId: this.id,
                ruleName: this.name,
                severity: 'HIGH',
                filePath,
                line: 1,
                message: 'DORA ART. 28-44: No third-party ICT provider risk assessment found. Critical and important functions relying on external providers must be documented.',
                recommendation: 'Maintain a register of all ICT third-party providers with risk classifications and exit strategies per DORA Art. 28.',
            });
        }

        // 3. Incident Reporting (Art. 17-23)
        const hasIncidentReporting =
            lower.includes('incident report') ||
            lower.includes('incident response') ||
            lower.includes('ict incident') ||
            lower.includes('breach notification');

        if (!hasIncidentReporting) {
            findings.push({
                ruleId: this.id,
                ruleName: this.name,
                severity: 'HIGH',
                filePath,
                line: 1,
                message: 'DORA ART. 17-23: No ICT incident reporting protocol detected. Major ICT incidents must be reported to competent authorities within 4 hours.',
                recommendation: 'Implement incident classification, reporting timelines, and notification procedures per DORA Art. 17-23.',
            });
        }

        // 4. Resilience Testing (Art. 24-27)
        const hasResilienceTesting =
            lower.includes('resilience test') ||
            lower.includes('penetration test') ||
            lower.includes('threat-led') ||
            lower.includes('tlpt') ||
            lower.includes('red team');

        if (!hasResilienceTesting) {
            findings.push({
                ruleId: this.id,
                ruleName: this.name,
                severity: 'MEDIUM',
                filePath,
                line: 1,
                message: 'DORA ART. 24-27: No digital operational resilience testing evidence found. Significant entities must conduct threat-led penetration testing (TLPT).',
                recommendation: 'Document resilience testing program including vulnerability assessments and TLPT per DORA Art. 24-27.',
            });
        }

        return findings;
    },
};
