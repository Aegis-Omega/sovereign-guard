import * as crypto from 'crypto';
import { GuardReport, PatchResult, Invoice, InvoiceLineItem } from './types';

/**
 * SOVEREIGN GUARD — Billing Engine (Era 58)
 *
 * Converts audit reports and remediation activity into billable invoices.
 * Pricing is deterministic and anchored to regulatory severity.
 */

// ─── Pricing Model (USD cents) ────────────────────────────────────

const PRICE_PER_CRITICAL = 500;   // $5.00
const PRICE_PER_HIGH = 200;   // $2.00
const PRICE_PER_MEDIUM = 50;    // $0.50
const PRICE_PER_LOW = 0;     // Free (goodwill)
const PRICE_PER_TOKEN = 0.05;  // $0.0005 per token (cents)
const PRICE_PER_SEAL = 2500;  // $25.00

// ─── EU Pricing Model (EUR cents) ─────────────────────────────────

const EU_PRICE_PER_CRITICAL = 5000;  // €50.00
const EU_PRICE_PER_HIGH = 2000;      // €20.00
const EU_PRICE_PER_MEDIUM = 500;     // €5.00
const EU_PRICE_PER_LOW = 0;
const EU_PRICE_PER_TOKEN = 0.10;
const EU_PRICE_PER_SEAL = 25000;     // €250.00

// ─── Invoice Generator ───────────────────────────────────────────

export function calculateInvoice(
    report: GuardReport,
    patches: PatchResult[],
    clientName: string,
): Invoice {
    const lineItems: InvoiceLineItem[] = [];

    if (report.critical > 0) {
        lineItems.push({
            description: 'CRITICAL Violation Remediation',
            quantity: report.critical,
            unitPrice: PRICE_PER_CRITICAL,
            total: report.critical * PRICE_PER_CRITICAL,
        });
    }

    if (report.high > 0) {
        lineItems.push({
            description: 'HIGH Severity Audit Finding',
            quantity: report.high,
            unitPrice: PRICE_PER_HIGH,
            total: report.high * PRICE_PER_HIGH,
        });
    }

    if (report.medium > 0) {
        lineItems.push({
            description: 'MEDIUM Severity Audit Finding',
            quantity: report.medium,
            unitPrice: PRICE_PER_MEDIUM,
            total: report.medium * PRICE_PER_MEDIUM,
        });
    }

    const totalTokens = patches.reduce((sum, p) => sum + p.tokensUsed, 0);
    if (totalTokens > 0) {
        const tokenCost = Math.ceil(totalTokens * PRICE_PER_TOKEN);
        lineItems.push({
            description: 'AI Metabolism (Token Passthrough)',
            quantity: totalTokens,
            unitPrice: PRICE_PER_TOKEN,
            total: tokenCost,
        });
    }

    if (report.seal) {
        lineItems.push({
            description: 'Cryptographic Provenance Seal',
            quantity: 1,
            unitPrice: PRICE_PER_SEAL,
            total: PRICE_PER_SEAL,
        });
    }

    const subtotal = lineItems.reduce((sum, item) => sum + item.total, 0);
    const id = `INV-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

    return {
        id,
        timestamp: new Date().toISOString(),
        clientName,
        targetDir: report.targetDir,
        lineItems,
        subtotal,
        sealHash: report.seal?.hash || 'UNSIGNED',
        status: 'DRAFT',
        currency: 'USD',
    };
}

// ─── EU Invoice Generator ─────────────────────────────────────────

export function calculateEUInvoice(
    report: GuardReport,
    patches: PatchResult[],
    clientName: string,
): Invoice {
    const lineItems: InvoiceLineItem[] = [];

    if (report.critical > 0) {
        lineItems.push({
            description: 'CRITICAL Violation (DORA/AI Act)',
            quantity: report.critical,
            unitPrice: EU_PRICE_PER_CRITICAL,
            total: report.critical * EU_PRICE_PER_CRITICAL,
        });
    }
    if (report.high > 0) {
        lineItems.push({
            description: 'HIGH Severity Compliance Finding',
            quantity: report.high,
            unitPrice: EU_PRICE_PER_HIGH,
            total: report.high * EU_PRICE_PER_HIGH,
        });
    }
    if (report.medium > 0) {
        lineItems.push({
            description: 'MEDIUM Severity Compliance Finding',
            quantity: report.medium,
            unitPrice: EU_PRICE_PER_MEDIUM,
            total: report.medium * EU_PRICE_PER_MEDIUM,
        });
    }

    const totalTokens = patches.reduce((sum, p) => sum + p.tokensUsed, 0);
    if (totalTokens > 0) {
        lineItems.push({
            description: 'AI Metabolism (Token Passthrough)',
            quantity: totalTokens,
            unitPrice: EU_PRICE_PER_TOKEN,
            total: Math.ceil(totalTokens * EU_PRICE_PER_TOKEN),
        });
    }

    if (report.seal) {
        lineItems.push({
            description: 'Sovereign Compliance Seal (EU)',
            quantity: 1,
            unitPrice: EU_PRICE_PER_SEAL,
            total: EU_PRICE_PER_SEAL,
        });
    }

    const subtotal = lineItems.reduce((sum, item) => sum + item.total, 0);
    const id = `INV-EU-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

    return {
        id,
        timestamp: new Date().toISOString(),
        clientName,
        targetDir: report.targetDir,
        lineItems,
        subtotal,
        sealHash: report.seal?.hash || 'UNSIGNED',
        status: 'DRAFT',
        currency: 'EUR',
    };
}

// ─── Markdown Formatter ───────────────────────────────────────────

export function formatInvoiceMarkdown(invoice: Invoice): string {
    const currencySymbol = invoice.currency === 'EUR' ? '€' : '$';
    const complianceEngine = invoice.currency === 'EUR'
        ? 'DORA (2022/2554) / EU AI Act (2024/1689)'
        : 'HIPAA-2026 / PSD3';
    const lines: string[] = [
        `# Guard Professional — Invoice`,
        ``,
        `| Field | Value |`,
        `| --- | --- |`,
        `| **Invoice ID** | \`${invoice.id}\` |`,
        `| **Date** | ${invoice.timestamp.split('T')[0]} |`,
        `| **Client** | ${invoice.clientName} |`,
        `| **Target** | \`${invoice.targetDir}\` |`,
        `| **Currency** | ${invoice.currency || 'USD'} |`,
        `| **Status** | **${invoice.status}** |`,
        `| **Provenance Seal** | \`${invoice.sealHash.slice(0, 16)}...\` |`,
        ``,
        `## Line Items`,
        ``,
        `| Description | Qty | Unit Price | Total |`,
        `| --- | ---: | ---: | ---: |`,
    ];

    for (const item of invoice.lineItems) {
        lines.push(`| ${item.description} | ${item.quantity} | ${currencySymbol}${(item.unitPrice / 100).toFixed(2)} | ${currencySymbol}${(item.total / 100).toFixed(2)} |`);
    }

    lines.push(`| | | **Subtotal** | **${currencySymbol}${(invoice.subtotal / 100).toFixed(2)}** |`);
    lines.push(``);
    lines.push(`---`);
    lines.push(`*Generated by Guard Professional (1.0.0-beta.1)*`);
    lines.push(`*Compliance Engine: ${complianceEngine}*`);

    return lines.join('\n');
}

// ─── JSON Formatter ───────────────────────────────────────────────

export function formatInvoiceJSON(invoice: Invoice): string {
    return JSON.stringify(invoice, null, 2);
}

// ─── Compliance Risk Letter ───────────────────────────────────────

export function generateComplianceLetter(invoice: Invoice): string {
    const date = invoice.timestamp.split('T')[0];
    const isEU = invoice.currency === 'EUR';
    const currencySymbol = isEU ? '€' : '$';
    const findings = invoice.lineItems
        .filter(i => i.description !== 'Cryptographic Provenance Seal' && i.description !== 'Sovereign Compliance Seal (EU)' && i.description !== 'AI Metabolism (Token Passthrough)')
        .map(i => `  - ${i.quantity} ${i.description}(s)`)
        .join('\n');

    const regulatoryRef = isEU
        ? '**DORA (EU 2022/2554)** and **EU AI Act (2024/1689)**'
        : '**HIPAA-2026** (45 CFR § 164.312) and/or **PSD3**';
    const penaltyRef = isEU
        ? 'up to **7% of global annual turnover or €35,000,000** under the EU AI Act, and up to **1% of average daily worldwide turnover** under DORA'
        : 'up to **$2.1M per annum**';
    const auditTrailRef = isEU
        ? 'DORA Art. 5-16 / EU AI Act Title III'
        : '45 CFR § 164.312';

    return [
        `# LETTER OF COMPLIANCE RISK`,
        ``,
        `**Date**: ${date}`,
        `**To**: Chief Compliance Officer, ${invoice.clientName}`,
        `**From**: Guard Professional — Automated Compliance Division`,
        `**Re**: Regulatory Audit Findings — Invoice ${invoice.id}`,
        ``,
        `---`,
        ``,
        `Dear Compliance Officer,`,
        ``,
        `This letter serves as formal notification that a regulatory compliance audit conducted by **Guard Professional** has identified the following findings within your organization's codebase:`,
        ``,
        findings,
        ``,
        `These findings represent potential violations of ${regulatoryRef} regulatory frameworks. Under current enforcement guidelines, unresolved findings of this nature may expose your organization to penalties of ${penaltyRef}.`,
        ``,
        `## Recommended Action`,
        ``,
        `Guard Professional offers automated, cryptographically sealed remediation for all identified findings. The total remediation cost for your organization is:`,
        ``,
        `> **${currencySymbol}${(invoice.subtotal / 100).toFixed(2)}** (one-time)`,
        ``,
        `This fee includes:`,
        `- Automated code patching for all identified vulnerabilities`,
        `- A **Cryptographic Provenance Seal** certifying compliance finality`,
        `- A verifiable audit trail anchored to ${auditTrailRef}`,
        ``,
        `## Verification`,
        ``,
        `This letter is cryptographically sealed with hash:`,
        `\`${invoice.sealHash}\``,
        ``,
        `To proceed with remediation, contact your Guard Professional representative or visit your payment portal.`,
        ``,
        `---`,
        `*Guard Professional (1.0.0-beta.1) — Zero-Click Automated Compliance Engine*`,
    ].join('\n');
}
