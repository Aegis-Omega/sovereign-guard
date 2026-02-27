import * as fs from 'fs';
import * as path from 'path';
import { GuardConfig, GuardReport, Finding, Severity, SEVERITY_ORDER } from './types';
import { ALL_RULES } from './rules';
import { queryKnowledge } from './knowledge';

/**
 * SOVEREIGN GUARD — SovereignScanner (Era 55)
 * 
 * High-throughput asynchronous audit engine.
 */
export class SovereignScanner {
    private version = '1.1.0-RES';
    private config: GuardConfig;

    constructor(config: GuardConfig) {
        this.config = config;
    }

    /**
     * Entry point for scanning a target substrate.
     */
    async scan(targetPath: string): Promise<GuardReport> {
        const absoluteTarget = path.resolve(targetPath);
        if (!fs.existsSync(absoluteTarget)) {
            throw new Error(`Target not found: ${absoluteTarget}`);
        }

        const files = await this.collectFiles(absoluteTarget);
        const report = await this.execute(files, absoluteTarget);

        return report;
    }

    private async collectFiles(target: string): Promise<string[]> {
        const stats = await fs.promises.stat(target);
        if (stats.isFile()) return [target];

        const extensions = this.getExtensions();
        const files: string[] = [];

        const walk = async (currentDir: string) => {
            if (files.length >= this.config.maxFiles) return;

            const entries = await fs.promises.readdir(currentDir, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(currentDir, entry.name);
                const relativePath = path.relative(target, fullPath).replace(/\\/g, '/');

                if (this.isExcluded(relativePath)) continue;

                if (entry.isDirectory()) {
                    if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
                    await walk(fullPath);
                } else if (entry.isFile()) {
                    if (extensions.includes(path.extname(entry.name))) {
                        files.push(fullPath);
                    }
                }
            }
        };

        await walk(target);
        return files;
    }

    private async execute(files: string[], targetDir: string): Promise<GuardReport> {
        const enabledRules = ALL_RULES.filter(r => !this.config.disableRules.includes(r.id));
        const minSeverityOrder = SEVERITY_ORDER[this.config.minSeverity];
        const allFindings: Finding[] = [];

        await Promise.all(files.map(async (file) => {
            try {
                const content = await fs.promises.readFile(file, 'utf8');
                for (const rule of enabledRules) {
                    if (SEVERITY_ORDER[rule.severity] > minSeverityOrder) continue;

                    const findings = rule.check(content, file);

                    // Envisioned RAG Grounding: Anchor high-severity findings in regulatory truth
                    for (const finding of findings) {
                        if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
                            finding.shards = await queryKnowledge(finding.message);
                        }
                    }

                    allFindings.push(...findings);
                }
            } catch { /* skip inaccessible files */ }
        }));

        allFindings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

        const tokens = await this.calculateTokens(files);

        return {
            timestamp: new Date().toISOString(),
            version: this.version,
            targetDir,
            filesScanned: files.length,
            totalFindings: allFindings.length,
            critical: allFindings.filter(f => f.severity === 'CRITICAL').length,
            high: allFindings.filter(f => f.severity === 'HIGH').length,
            medium: allFindings.filter(f => f.severity === 'MEDIUM').length,
            low: allFindings.filter(f => f.severity === 'LOW').length,
            findings: allFindings,
            cognitiveROI: tokens > 0 ? (allFindings.length / tokens) : 0,
            tokensConsumed: tokens
        };
    }

    private getExtensions(): string[] {
        const exts = this.config.include.map(p => path.extname(p)).filter(Boolean);
        return exts.length > 0 ? exts : ['.ts', '.js', '.md', '.json'];
    }

    private isExcluded(relPath: string): boolean {
        return this.config.exclude.some(pattern => {
            const clean = pattern.replace(/\*\*/g, '').replace(/\*/g, '');
            return relPath.includes(clean.replace(/\//g, ''));
        });
    }

    private async calculateTokens(files: string[]): Promise<number> {
        let totalSize = 0;
        for (const file of files) {
            try {
                const s = await fs.promises.stat(file);
                totalSize += s.size;
            } catch { continue; }
        }
        return Math.ceil(totalSize / 4);
    }
}

/** Legacy support wrapper */
export async function runScan(target: string, config: GuardConfig): Promise<GuardReport> {
    const scanner = new SovereignScanner(config);
    return scanner.scan(target);
}
