/**
 * SOVEREIGN GUARD — Core Type System
 *
 * Clean, enterprise-grade interfaces for the audit engine.
 */

// ─── Findings ─────────────────────────────────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export const SEVERITY_ORDER: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
};

export interface KnowledgeShard {
    id: string;
    title: string;
    content: string;
    citation: string;
}

export interface Finding {
    ruleId: string;
    ruleName: string;
    severity: Severity;
    filePath: string;
    line?: number;
    message: string;
    recommendation: string;
    shards?: KnowledgeShard[]; // Grounded regulatory context
}

// ─── Rules ────────────────────────────────────────────────────────

export interface Rule {
    id: string;
    name: string;
    severity: Severity;
    description: string;
    check(content: string, filePath: string): Finding[];
}

// ─── Patches ──────────────────────────────────────────────────────

export interface PatchResult {
    filePath: string;
    finding: Finding;
    patch: string;
    live: boolean;
    model: string;
    tokensUsed: number;
}

// ─── Provenance Seal ──────────────────────────────────────────────

export interface ProvenanceSeal {
    hash: string;
    timestamp: string;
    filesSealed: number;
    rulesApplied: string[];
    findingsAtSeal: number;
    version: string;
}

// ─── Configuration ────────────────────────────────────────────────

export interface GuardConfig {
    /** Glob patterns to include */
    include: string[];
    /** Glob patterns to exclude */
    exclude: string[];
    /** Rules to disable by ID */
    disableRules: string[];
    /** Severity threshold — only report findings at or above this level */
    minSeverity: Severity;
    /** Max files to scan (performance guard) */
    maxFiles: number;
}

export const DEFAULT_CONFIG: GuardConfig = {
    include: ['**/*.ts', '**/*.js'],
    exclude: ['node_modules/**', 'dist/**', '.next/**', 'coverage/**', '*.d.ts'],
    disableRules: [],
    minSeverity: 'LOW',
    maxFiles: 500,
};

// ─── Report ───────────────────────────────────────────────────────

export interface GuardReport {
    timestamp: string;
    version: string;
    targetDir: string;
    filesScanned: number;
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    findings: Finding[];
    seal?: ProvenanceSeal;
    // Era 50 Metrics
    cognitiveROI?: number; // Density of Truth: findings / tokens
    tokensConsumed?: number;
}

// ─── Billing (Era 58) ─────────────────────────────────────────────

export interface InvoiceLineItem {
    description: string;
    quantity: number;
    unitPrice: number;  // USD cents
    total: number;      // USD cents
}

export interface Invoice {
    id: string;
    timestamp: string;
    clientName: string;
    targetDir: string;
    lineItems: InvoiceLineItem[];
    subtotal: number;   // smallest currency unit (cents/euro-cents)
    sealHash: string;
    status: 'DRAFT' | 'DISPATCHED' | 'PAID';
    currency?: 'USD' | 'EUR';
}
