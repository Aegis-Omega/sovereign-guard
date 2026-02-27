import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { GuardReport, ProvenanceSeal } from './types';

/**
 * SOVEREIGN GUARD — Provenance Seal
 *
 * Generates a cryptographic seal over the codebase state.
 * The seal proves the code was audited at a specific point in time.
 */

const VERSION = '1.0.0';

/**
 * Generate a Sovereign Provenance Seal for a scanned codebase.
 */
export function generateSeal(report: GuardReport, targetDir: string): ProvenanceSeal {
    // Create a deterministic hash over the scan results
    const payload = JSON.stringify({
        timestamp: report.timestamp,
        filesScanned: report.filesScanned,
        totalFindings: report.totalFindings,
        findings: report.findings.map(f => ({
            rule: f.ruleId,
            file: path.relative(targetDir, f.filePath),
            line: f.line,
            severity: f.severity,
        })),
    });

    const hash = crypto.createHash('sha256').update(payload).digest('hex');

    const seal: ProvenanceSeal = {
        hash,
        timestamp: new Date().toISOString(),
        filesSealed: report.filesScanned,
        rulesApplied: [...new Set(report.findings.map(f => f.ruleId))],
        findingsAtSeal: report.totalFindings,
        version: VERSION,
    };

    return seal;
}

/**
 * Write the seal to a .sovereign-seal.json file in the target directory.
 */
export function persistSeal(seal: ProvenanceSeal, targetDir: string): string {
    const sealPath = path.join(targetDir, '.sovereign-seal.json');
    fs.writeFileSync(sealPath, JSON.stringify(seal, null, 2), 'utf8');
    return sealPath;
}

/**
 * Read an existing seal from a directory.
 */
export function readSeal(targetDir: string): ProvenanceSeal | null {
    const sealPath = path.join(targetDir, '.sovereign-seal.json');
    if (!fs.existsSync(sealPath)) return null;

    try {
        return JSON.parse(fs.readFileSync(sealPath, 'utf8'));
    } catch {
        return null;
    }
}
