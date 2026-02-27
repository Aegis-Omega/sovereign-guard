import * as path from 'path';
import { GuardReport, Finding, PatchResult, ProvenanceSeal } from './types';

/**
 * SOVEREIGN GUARD — Report Formatters
 *
 * Terminal (default), JSON, and Markdown output.
 */

// ─── ANSI Colors ──────────────────────────────────────────────────
export const RESET = '\x1b[0m';
export const BOLD = '\x1b[1m';
export const DIM = '\x1b[2m';
export const RED = '\x1b[31m';
export const YELLOW = '\x1b[33m';
export const GREEN = '\x1b[32m';
export const CYAN = '\x1b[36m';
export const MAGENTA = '\x1b[35m';
export const WHITE = '\x1b[37m';
export const BG_RED = '\x1b[41m';

function severityColor(severity: string): string {
    switch (severity) {
        case 'CRITICAL': return `${BG_RED}${WHITE}${BOLD}`;
        case 'HIGH': return `${RED}${BOLD}`;
        case 'MEDIUM': return `${YELLOW}`;
        case 'LOW': return `${DIM}`;
        default: return '';
    }
}

function severityIcon(severity: string): string {
    switch (severity) {
        case 'CRITICAL': return '✗';
        case 'HIGH': return '!';
        case 'MEDIUM': return '~';
        case 'LOW': return '·';
        default: return ' ';
    }
}

// ─── Terminal Reporter ────────────────────────────────────────────

export function reportTerminal(report: GuardReport): string {
    const lines: string[] = [];

    lines.push('');
    lines.push(`${BOLD}${CYAN}  ◈ SOVEREIGN GUARD — Code Audit Report${RESET}`);
    lines.push(`${DIM}  ═══════════════════════════════════════════════════${RESET}`);
    lines.push(`${DIM}  Target:   ${report.targetDir}${RESET}`);
    lines.push(`${DIM}  Scanned:  ${report.filesScanned} files${RESET}`);
    if (report.tokensConsumed) {
        lines.push(`${DIM}  Metabolism: ${report.tokensConsumed.toLocaleString()} tokens consumed${RESET}`);
    }
    if (report.cognitiveROI !== undefined) {
        const dot = (report.cognitiveROI * 1000).toFixed(4);
        lines.push(`${DIM}  Cognitive ROI: ${BOLD}${MAGENTA}${dot} Φ (Findings/kTokens)${RESET}`);
    }
    lines.push(`${DIM}  Time:     ${report.timestamp}${RESET}`);
    lines.push('');

    if (report.findings.length === 0) {
        lines.push(`${GREEN}${BOLD}  ✓ No issues found. Your code is clean.${RESET}`);
        lines.push('');
        return lines.join('\n');
    }

    // Group by file
    const byFile = new Map<string, Finding[]>();
    for (const f of report.findings) {
        const rel = path.relative(report.targetDir, f.filePath).replace(/\\/g, '/');
        if (!byFile.has(rel)) byFile.set(rel, []);
        byFile.get(rel)!.push(f);
    }

    for (const [file, findings] of byFile) {
        lines.push(`${BOLD}  ${file}${RESET}`);

        for (const f of findings) {
            const color = severityColor(f.severity);
            const icon = severityIcon(f.severity);
            const lineRef = f.line ? `:${f.line}` : '';
            lines.push(`    ${color}${icon} [${f.severity}]${RESET} ${f.message}`);
            lines.push(`${DIM}      → ${f.recommendation}${RESET}`);

            if (f.shards && f.shards.length > 0) {
                for (const shard of f.shards) {
                    lines.push(`${DIM}      📖 ${shard.citation}: ${shard.title}${RESET}`);
                }
            }
        }
        lines.push('');
    }

    // Summary bar
    lines.push(`${DIM}  ═══════════════════════════════════════════════════${RESET}`);

    const summary: string[] = [];
    if (report.critical > 0) summary.push(`${RED}${BOLD}${report.critical} CRITICAL${RESET}`);
    if (report.high > 0) summary.push(`${RED}${report.high} HIGH${RESET}`);
    if (report.medium > 0) summary.push(`${YELLOW}${report.medium} MEDIUM${RESET}`);
    if (report.low > 0) summary.push(`${DIM}${report.low} LOW${RESET}`);

    lines.push(`  ${BOLD}${report.totalFindings} findings${RESET}: ${summary.join(' | ')}`);

    if (report.critical > 0) {
        lines.push(`  ${RED}${BOLD}✗ CRITICAL issues require immediate attention.${RESET}`);
    }
    lines.push('');

    return lines.join('\n');
}

// ─── Patch Reporter ───────────────────────────────────────────────

export function reportPatches(patches: PatchResult[]): string {
    const lines: string[] = [];

    lines.push('');
    lines.push(`${BOLD}${MAGENTA}  ◈ SOVEREIGN GUARD — AI Patches${RESET}`);
    lines.push(`${DIM}  ═══════════════════════════════════════════════════${RESET}`);
    lines.push('');

    for (const p of patches) {
        const tag = p.live ? `${GREEN}[LIVE]${RESET}` : `${DIM}[OFFLINE]${RESET}`;
        lines.push(`  ${tag} ${BOLD}${path.basename(p.filePath)}${RESET} — ${p.finding.ruleId}`);

        if (p.live) {
            lines.push(`${DIM}  Model: ${p.model} | Tokens: ${p.tokensUsed}${RESET}`);
        }

        lines.push(`${CYAN}  ┌─────────────────────────────────────────────${RESET}`);
        for (const patchLine of p.patch.split('\n')) {
            lines.push(`${CYAN}  │${RESET} ${patchLine}`);
        }
        lines.push(`${CYAN}  └─────────────────────────────────────────────${RESET}`);
        lines.push('');
    }

    return lines.join('\n');
}

// ─── Seal Reporter ────────────────────────────────────────────────

export function reportSeal(seal: ProvenanceSeal): string {
    const lines: string[] = [];

    lines.push('');
    lines.push(`${BOLD}${GREEN}  ◈ SOVEREIGN PROVENANCE SEAL${RESET}`);
    lines.push(`${DIM}  ═══════════════════════════════════════════════════${RESET}`);
    lines.push(`  Hash:      ${BOLD}${seal.hash}${RESET}`);
    lines.push(`  Timestamp: ${seal.timestamp}`);
    lines.push(`  Files:     ${seal.filesSealed}`);
    lines.push(`  Rules:     ${seal.rulesApplied.length}`);
    lines.push(`  Findings:  ${seal.findingsAtSeal}`);
    lines.push(`  Version:   sovereign-guard@${seal.version}`);
    lines.push(`${DIM}  ═══════════════════════════════════════════════════${RESET}`);
    lines.push(`  ${GREEN}${BOLD}✓ Codebase sealed. Provenance verified.${RESET}`);
    lines.push('');

    return lines.join('\n');
}

// ─── JSON Reporter ────────────────────────────────────────────────

export function reportJSON(report: GuardReport): string {
    return JSON.stringify(report, null, 2);
}

// ─── Markdown Reporter ────────────────────────────────────────────

export function reportMarkdown(report: GuardReport): string {
    const lines: string[] = [];

    lines.push('# ◈ Sovereign Guard — Audit Report');
    lines.push('');
    lines.push(`| Metric | Value |`);
    lines.push(`|:---|:---|`);
    lines.push(`| Target | \`${report.targetDir}\` |`);
    lines.push(`| Files Scanned | ${report.filesScanned} |`);
    lines.push(`| Total Findings | **${report.totalFindings}** |`);
    lines.push(`| Critical | ${report.critical} |`);
    lines.push(`| High | ${report.high} |`);
    lines.push(`| Medium | ${report.medium} |`);
    lines.push(`| Low | ${report.low} |`);
    if (report.tokensConsumed) {
        lines.push(`| Tokens Consumed | ${report.tokensConsumed.toLocaleString()} |`);
    }
    if (report.cognitiveROI !== undefined) {
        lines.push(`| Cognitive ROI | **${(report.cognitiveROI * 1000).toFixed(4)} Φ** |`);
    }
    lines.push(`| Timestamp | ${report.timestamp} |`);
    lines.push('');

    if (report.findings.length === 0) {
        lines.push('✅ **No issues found. Your code is clean.**');
        return lines.join('\n');
    }

    lines.push('## Findings');
    lines.push('');

    // Group by severity
    for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const) {
        const group = report.findings.filter(f => f.severity === severity);
        if (group.length === 0) continue;

        lines.push(`### ${severity} (${group.length})`);
        lines.push('');

        for (const f of group) {
            const rel = path.relative(report.targetDir, f.filePath).replace(/\\/g, '/');
            lines.push(`- **${rel}${f.line ? ':' + f.line : ''}** — ${f.message}`);
            lines.push(`  - Fix: ${f.recommendation}`);
            if (f.shards && f.shards.length > 0) {
                for (const shard of f.shards) {
                    lines.push(`  - 📖 **${shard.citation}**: ${shard.content}`);
                }
            }
        }
        lines.push('');
    }

    if (report.seal) {
        lines.push('## Provenance Seal');
        lines.push(`- **Hash:** \`${report.seal.hash}\``);
        lines.push(`- **Sealed:** ${report.seal.timestamp}`);
    }

    return lines.join('\n');
}
