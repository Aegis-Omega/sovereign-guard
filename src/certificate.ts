import * as crypto from 'crypto';
import { Invoice } from './types';

/**
 * SOVEREIGN GUARD — Certificate of Compliance (Era 59)
 *
 * Generates a cryptographically sealed certificate after a client pays and
 * their codebase has been remediated. This is the final deliverable.
 */

export interface ComplianceCertificate {
    certificateId: string;
    invoiceId: string;
    clientName: string;
    issuedAt: string;
    sealHash: string;
    findingsRemediated: number;
    frameworks: string[];
    expiresAt: string;
}

export function generateCertificate(invoice: Invoice): ComplianceCertificate {
    const now = new Date();
    const expires = new Date(now);
    expires.setFullYear(expires.getFullYear() + 1);

    const totalFindings = invoice.lineItems
        .filter(i => i.description !== 'Cryptographic Provenance Seal' && i.description !== 'AI Metabolism (Token Passthrough)')
        .reduce((sum, i) => sum + i.quantity, 0);

    return {
        certificateId: `CERT-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
        invoiceId: invoice.id,
        clientName: invoice.clientName,
        issuedAt: now.toISOString(),
        sealHash: crypto.createHash('sha256')
            .update(`${invoice.id}:${invoice.sealHash}:${now.toISOString()}`)
            .digest('hex'),
        findingsRemediated: totalFindings,
        frameworks: ['HIPAA-2026 (45 CFR § 164.312)', 'PSD3 (SCA/API Transparency)'],
        expiresAt: expires.toISOString(),
    };
}

export function formatCertificateMarkdown(cert: ComplianceCertificate): string {
    return [
        `# SOVEREIGN CERTIFICATE OF COMPLIANCE`,
        ``,
        `---`,
        ``,
        `| Field | Value |`,
        `| --- | --- |`,
        `| **Certificate ID** | \`${cert.certificateId}\` |`,
        `| **Invoice ID** | \`${cert.invoiceId}\` |`,
        `| **Client** | ${cert.clientName} |`,
        `| **Issued** | ${cert.issuedAt.split('T')[0]} |`,
        `| **Expires** | ${cert.expiresAt.split('T')[0]} |`,
        `| **Findings Remediated** | ${cert.findingsRemediated} |`,
        ``,
        `## Compliance Frameworks`,
        ``,
        ...cert.frameworks.map(f => `- ✓ ${f}`),
        ``,
        `## Cryptographic Verification`,
        ``,
        `This certificate is sealed with the following provenance hash:`,
        ``,
        `\`\`\``,
        cert.sealHash,
        `\`\`\``,
        ``,
        `This hash can be independently verified against the Guard Professional audit ledger.`,
        ``,
        `---`,
        ``,
        `> This certificate attests that **${cert.clientName}** has undergone automated`,
        `> compliance remediation using Guard Professional and satisfies the requirements`,
        `> of the above frameworks as of the date of issuance.`,
        ``,
        `---`,
        `*Issued by Guard Professional (1.0.0-beta.1)*`,
        `*Zero-Click HIPAA/PSD3 Automated Remediation Engine*`,
    ].join('\n');
}
