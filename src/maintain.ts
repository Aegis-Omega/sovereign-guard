import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { formatInvoiceMarkdown, generateComplianceLetter } from './billing';
import { Invoice } from './types';

/**
 * SOVEREIGN GUARD — Maintenance Engine (Era 66)
 *
 * Certificate expiry watcher with autonomous renewal invoice staging.
 * Scans vault/Certificates/ for certificates approaching expiry,
 * generates discounted renewal invoices, and dispatches them.
 *
 * Features:
 * - Configurable expiry threshold (default: 90 days)
 * - 20% "Sovereign Loyalty" renewal discount
 * - Multi-currency renewal (USD/EUR)
 * - Renewal letter generation with expiry urgency
 */

export interface MaintenanceConfig {
    certDir: string;
    invoiceDir: string;
    letterDir: string;
    expiryThresholdDays: number;  // Flag certs expiring within N days
    renewalDiscount: number;      // Discount percentage (0.20 = 20%)
}

export interface CertStatus {
    certificateId: string;
    clientName: string;
    expiresAt: string;
    daysRemaining: number;
    currency: 'USD' | 'EUR';
    status: 'ACTIVE' | 'EXPIRING' | 'EXPIRED';
}

export interface MaintenanceReport {
    scanDate: string;
    totalCertificates: number;
    active: number;
    expiring: number;
    expired: number;
    renewalInvoicesGenerated: number;
    projectedRenewalRevenue: number;
    certificates: CertStatus[];
}

/**
 * Parse a certificate markdown file and extract metadata.
 */
function parseCertificate(filePath: string): CertStatus | null {
    const content = fs.readFileSync(filePath, 'utf8');

    const idMatch = content.match(/Certificate ID[^`]*`([^`]+)`/) ||
        content.match(/CERT-[\w-]+/);
    const clientMatch = content.match(/Client[^|]*\|\s*([^|\n]+)/) ||
        content.match(/Issued To[^|]*\|\s*([^|\n]+)/);
    const expiryMatch = content.match(/Expires?[^|]*\|\s*([0-9]{4}-[0-9]{2}-[0-9]{2})/) ||
        content.match(/Valid Until[^|]*\|\s*([0-9]{4}-[0-9]{2}-[0-9]{2})/);
    const currencyMatch = content.match(/Currency[^|]*\|\s*(USD|EUR)/);

    if (!idMatch || !expiryMatch) return null;

    const certificateId = idMatch[1]?.trim() || idMatch[0]?.trim() || 'UNKNOWN';
    const clientName = clientMatch?.[1]?.trim() || 'Unknown Client';
    const expiresAt = expiryMatch[1].trim();
    const currency = (currencyMatch?.[1]?.trim() || (content.includes('EUR') ? 'EUR' : 'USD')) as 'USD' | 'EUR';

    const now = new Date();
    const expiry = new Date(expiresAt);
    const msPerDay = 86400000;
    const daysRemaining = Math.floor((expiry.getTime() - now.getTime()) / msPerDay);

    let status: 'ACTIVE' | 'EXPIRING' | 'EXPIRED';
    if (daysRemaining < 0) {
        status = 'EXPIRED';
    } else if (daysRemaining <= 90) {
        status = 'EXPIRING';
    } else {
        status = 'ACTIVE';
    }

    return { certificateId, clientName, expiresAt, daysRemaining, currency, status };
}

/**
 * Generate a renewal invoice for an expiring certificate.
 */
function generateRenewalInvoice(
    cert: CertStatus,
    discount: number,
): Invoice {
    const isEU = cert.currency === 'EUR';

    // Base renewal pricing (same as original, minus discount)
    const baseSealPrice = isEU ? 25000 : 2500;
    const baseAuditFee = isEU ? 50000 : 10000; // flat re-audit fee
    const discountMultiplier = 1 - discount;

    const sealTotal = Math.round(baseSealPrice * discountMultiplier);
    const auditTotal = Math.round(baseAuditFee * discountMultiplier);
    const discountPct = Math.round(discount * 100);

    const lineItems = [
        {
            description: `Compliance Re-Audit (${discountPct}% Loyalty Discount)`,
            quantity: 1,
            unitPrice: auditTotal,
            total: auditTotal,
        },
        {
            description: `Sovereign Seal Renewal (${discountPct}% Loyalty Discount)`,
            quantity: 1,
            unitPrice: sealTotal,
            total: sealTotal,
        },
    ];

    const subtotal = lineItems.reduce((s, i) => s + i.total, 0);
    const id = `INV-REN-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

    return {
        id,
        timestamp: new Date().toISOString(),
        clientName: cert.clientName,
        targetDir: `Renewal: ${cert.certificateId}`,
        lineItems,
        subtotal,
        sealHash: crypto.createHash('sha256').update(`${cert.certificateId}:renewal:${Date.now()}`).digest('hex'),
        status: 'DRAFT',
        currency: cert.currency,
    };
}

/**
 * Run the maintenance sweep — scan certificates, flag expirations, stage renewals.
 */
export function runMaintenance(
    config: MaintenanceConfig,
    onProgress?: (scanned: number, total: number) => void,
): MaintenanceReport {
    const scanDate = new Date().toISOString();

    if (!fs.existsSync(config.certDir)) {
        return {
            scanDate,
            totalCertificates: 0,
            active: 0,
            expiring: 0,
            expired: 0,
            renewalInvoicesGenerated: 0,
            projectedRenewalRevenue: 0,
            certificates: [],
        };
    }

    [config.invoiceDir, config.letterDir].forEach(d => {
        if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    });

    const files = fs.readdirSync(config.certDir)
        .filter(f => f.startsWith('CERT-') && f.endsWith('.md'));

    const certificates: CertStatus[] = [];
    let renewalCount = 0;
    let renewalRevenue = 0;

    for (let i = 0; i < files.length; i++) {
        const cert = parseCertificate(path.join(config.certDir, files[i]));
        if (!cert) continue;

        // Override threshold check with config
        if (cert.daysRemaining <= config.expiryThresholdDays && cert.daysRemaining >= 0) {
            cert.status = 'EXPIRING';
        }

        certificates.push(cert);

        // Generate renewal invoices for EXPIRING certificates
        if (cert.status === 'EXPIRING' || cert.status === 'EXPIRED') {
            const invoice = generateRenewalInvoice(cert, config.renewalDiscount);

            // Save renewal invoice
            const invoiceMd = formatInvoiceMarkdown(invoice);
            fs.writeFileSync(path.join(config.invoiceDir, `${invoice.id}.md`), invoiceMd, 'utf8');

            // Generate renewal letter
            const letter = generateComplianceLetter(invoice);
            fs.writeFileSync(path.join(config.letterDir, `LETTER-${invoice.id}.md`), letter, 'utf8');

            renewalCount++;
            renewalRevenue += invoice.subtotal;
        }

        if (onProgress && ((i + 1) % 500 === 0 || i === files.length - 1)) {
            onProgress(i + 1, files.length);
        }
    }

    return {
        scanDate,
        totalCertificates: certificates.length,
        active: certificates.filter(c => c.status === 'ACTIVE').length,
        expiring: certificates.filter(c => c.status === 'EXPIRING').length,
        expired: certificates.filter(c => c.status === 'EXPIRED').length,
        renewalInvoicesGenerated: renewalCount,
        projectedRenewalRevenue: renewalRevenue,
        certificates,
    };
}

/**
 * Format maintenance report as markdown.
 */
export function formatMaintenanceReport(report: MaintenanceReport): string {
    const lines = [
        `# ◈ Sovereign Vigil — Maintenance Report`,
        ``,
        `**Scan Date**: ${report.scanDate.split('T')[0]}`,
        ``,
        `## Certificate Status`,
        ``,
        `| Metric | Value |`,
        `| --- | --- |`,
        `| **Total Certificates** | ${report.totalCertificates} |`,
        `| **Active (>90 days)** | ${report.active} |`,
        `| **Expiring (≤90 days)** | ${report.expiring} |`,
        `| **Expired** | ${report.expired} |`,
        ``,
        `## Renewal Pipeline`,
        ``,
        `| Metric | Value |`,
        `| --- | --- |`,
        `| **Renewal Invoices Staged** | ${report.renewalInvoicesGenerated} |`,
        `| **Projected Renewal Revenue** | ~$${(report.projectedRenewalRevenue / 100).toFixed(2)} |`,
        `| **Discount Applied** | 20% Sovereign Loyalty |`,
        ``,
        `---`,
        `*Guard Professional (1.0.0) — Sovereign Vigil (Era 66)*`,
        `*[ACTA NON VERBA]* ◈`,
    ];
    return lines.join('\n');
}
