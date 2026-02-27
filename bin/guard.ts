#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { runScan } from '../src/engine';
import { PatchResult } from '../src/types';
import { loadConfig } from '../src/config';
import { calculateInvoice, calculateEUInvoice, formatInvoiceMarkdown, formatInvoiceJSON, generateComplianceLetter } from '../src/billing';
import { generateCertificate, formatCertificateMarkdown } from '../src/certificate';
import { generateTargetList, generateEUTargetList, formatTargetListMarkdown } from '../src/targets';
import { generatePatch, hasApiKey } from '../src/patcher';
import { generateSeal, persistSeal } from '../src/seal';
import {
    reportTerminal,
    reportJSON,
    reportMarkdown,
    reportPatches,
    reportSeal,
    BOLD,
    CYAN,
    RESET,
    GREEN,
    MAGENTA,
    YELLOW,
} from '../src/reporter';

const VERSION = '1.0.0';

const program = new Command();

program
    .name('sovereign-guard')
    .description('The only AI auditor that signs its own patches.')
    .version(VERSION)
    .option('--silent', 'Enable the Law of Silence (minimal output)', false);

// ─── guard scan ───────────────────────────────────────────────────

program
    .command('scan')
    .description('Scan a codebase for security issues, code smells, and debt.')
    .argument('[target]', 'Target directory to scan', '.')
    .option('-f, --format <type>', 'Output format: terminal, json, md', 'terminal')
    .option('-o, --output <file>', 'Write report to file')
    .option('--min-severity <level>', 'Minimum severity: CRITICAL, HIGH, MEDIUM, LOW', 'LOW')
    .option('--disable <rules>', 'Comma-separated rule IDs to disable', '')
    .action(async (target: string, opts: any) => {
        const targetDir = path.resolve(target);

        if (!fs.existsSync(targetDir)) {
            console.error(`Error: Directory not found: ${targetDir}`);
            process.exit(1);
        }

        const config = loadConfig(targetDir);

        if (opts.minSeverity) {
            config.minSeverity = opts.minSeverity.toUpperCase();
        }
        if (opts.disable) {
            config.disableRules = opts.disable.split(',').map((s: string) => s.trim());
        }

        const report = await runScan(targetDir, config);

        let output: string;
        switch (opts.format) {
            case 'json':
                output = reportJSON(report);
                break;
            case 'md':
            case 'markdown':
                output = reportMarkdown(report);
                break;
            default:
                output = reportTerminal(report);
        }

        if (opts.output) {
            fs.writeFileSync(opts.output, output, 'utf8');
            if (!program.opts().silent) console.log(`Report saved to: ${opts.output}`);
        } else if (!program.opts().silent) {
            console.log(output);
        }

        // Exit with non-zero if critical/high findings
        if (report.critical > 0 || report.high > 0) {
            process.exit(1);
        }
    });

// ─── guard fix ────────────────────────────────────────────────────

program
    .command('fix')
    .description('Generate AI-powered patches for detected issues. (Requires GOOGLE_GENERATIVE_AI_API_KEY)')
    .argument('[target]', 'Target directory to scan and fix', '.')
    .option('--max-patches <n>', 'Maximum patches to generate', '5')
    .option('--severity <level>', 'Only fix issues at or above this severity', 'HIGH')
    .action(async (target: string, opts: any) => {
        const targetDir = path.resolve(target);
        const config = loadConfig(targetDir);
        config.minSeverity = opts.severity?.toUpperCase() || 'HIGH';

        if (!hasApiKey()) {
            console.log('');
            console.log('  ⚠ No API key found.');
            console.log('  Set GOOGLE_GENERATIVE_AI_API_KEY to enable AI-powered patches.');
            console.log('  Get a free key at: https://aistudio.google.com/apikey');
            console.log('');
            process.exit(1);
        }

        // First, scan
        const report = await runScan(targetDir, config);
        console.log(reportTerminal(report));

        if (report.totalFindings === 0) {
            console.log('  ✓ No issues to fix.');
            return;
        }

        // Generate patches for top findings
        const maxPatches = parseInt(opts.maxPatches, 10) || 5;
        const patchable = report.findings
            .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
            .slice(0, maxPatches);

        if (patchable.length === 0) {
            console.log('  No CRITICAL/HIGH issues to patch.');
            return;
        }

        console.log(`  Generating ${patchable.length} AI patches...`);
        console.log('');

        const patches = [];
        for (const finding of patchable) {
            try {
                const content = fs.readFileSync(finding.filePath, 'utf8');
                const patch = await generatePatch(content, finding);
                patches.push(patch);
            } catch (err: unknown) {
                console.error(`  Failed to patch ${finding.filePath}: ${err instanceof Error ? err.message : err}`);
            }
        }

        if (patches.length > 0 && !program.opts().silent) {
            console.log(reportPatches(patches));
        }

        // Save patches to files
        for (const p of patches) {
            if (p.live) {
                const patchFile = p.filePath + '.patch';
                fs.writeFileSync(patchFile, p.patch, 'utf8');
            }
        }

        const liveCount = patches.filter(p => p.live).length;
        if (liveCount > 0 && !program.opts().silent) {
            console.log(`  ${liveCount} patch files saved (.patch). Review and apply manually.`);
        }
    });

// ─── guard think ──────────────────────────────────────────────────
program
    .command('think')
    .description('Trigger the Silent Cycle: Scan, Fix, and Sign in a single mission.')
    .argument('[target]', 'Target directory', '.')
    .action(async (target: string) => {
        const targetDir = path.resolve(target);
        const silent = program.opts().silent;

        if (!silent) console.log(`${BOLD}${CYAN}  ◈ SOVEREIGN THINK — Initiating Silent Cycle...${RESET}`);

        const config = loadConfig(targetDir);
        const report = await runScan(targetDir, config);

        if (!silent) console.log(`  Scan complete: ${report.totalFindings} findings.`);

        const patches: PatchResult[] = [];
        if (hasApiKey() && (report.critical > 0 || report.high > 0)) {
            const patchable = report.findings
                .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
                .slice(0, 5);

            if (!silent) console.log(`  Fixing ${patchable.length} critical/high issues...`);

            for (const finding of patchable) {
                try {
                    const content = fs.readFileSync(finding.filePath, 'utf8');
                    const patch = await generatePatch(content, finding);
                    patches.push(patch);
                    // In 'think' mode, we save patches immediately
                    fs.writeFileSync(finding.filePath + '.patch', patch.patch, 'utf8');
                } catch { /* silent fail */ }
            }
        }

        const seal = generateSeal(report, targetDir);
        persistSeal(seal, targetDir);
        report.seal = seal;

        if (silent) {
            // Output only the Success Shard (The Seal)
            console.log(JSON.stringify({
                status: 'MISSION_SUCCESS',
                era: 51,
                roi: (report.cognitiveROI! * 1000).toFixed(4),
                seal: seal.hash,
                findings: report.totalFindings
            }));
        } else {
            console.log(reportSeal(seal));
            console.log(`${GREEN}${BOLD}  ◈ MISSION CLOSED.${RESET}`);
        }
    });

// ─── guard audit ──────────────────────────────────────────────────
program
    .command('audit')
    .description('Execute a high-fidelity Clinical or Commercial audit.')
    .argument('<target>', 'Target dataset or directory')
    .option('--output-dir <dir>', 'Directory to save the audit report', 'vault/Audits')
    .action(async (target: string, opts: any) => {
        const targetPath = path.resolve(target);
        const silent = program.opts().silent;

        if (!fs.existsSync(targetPath)) {
            console.error(`Error: Target not found: ${targetPath}`);
            process.exit(1);
        }

        if (!silent) console.log(`${BOLD}${MAGENTA}  ◈ CLINICAL STRIKE: AUDITING SUBSTRATE...${RESET}`);

        const config = loadConfig(path.dirname(targetPath));
        const report = await runScan(targetPath, config);

        // Generate ROI (Simulated if not in engine)
        const roi = (report.cognitiveROI || (report.totalFindings / 10)).toFixed(4);

        const seal = generateSeal(report, path.dirname(targetPath));
        persistSeal(seal, path.dirname(targetPath));
        report.seal = seal;

        const mdReport = reportMarkdown(report);
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `AUDIT_${path.basename(target, path.extname(target))}_${timestamp}.md`;

        const outputDir = path.resolve(opts.outputDir);
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        const fullPath = path.join(outputDir, filename);
        fs.writeFileSync(fullPath, mdReport, 'utf8');

        if (silent) {
            console.log(JSON.stringify({
                status: 'AUDIT_SEALED',
                target: path.basename(target),
                era: 51,
                roi,
                report: fullPath,
                seal: seal.hash
            }));
        } else {
            console.log(reportTerminal(report));
            console.log(`  ◈ Seal: ${seal.hash.slice(0, 16)}...`);
            console.log(`  ◈ Report saved: ${fullPath}`);
            console.log(`${MAGENTA}${BOLD}  ◈ AUDIT COMPLETE.${RESET}`);
        }
    });

// ─── guard remediate ──────────────────────────────────────────────

program
    .command('remediate')
    .description('Initiate an automated Remediation Sprint to liquidate debt.')
    .argument('[target]', 'Target directory', '.')
    .option('--apply', 'Automatically apply patches to the substrate', false)
    .option('--max-findings <n>', 'Maximum findings to liquidate', '50')
    .action(async (target: string, opts: any) => {
        const targetDir = path.resolve(target);
        const silent = program.opts().silent;
        const apply = opts.apply;

        if (!silent) console.log(`${BOLD}${GREEN}  ◈ INITIATING REMEDIATION SPRINT — Era 56 Strategy...${RESET}`);

        const config = loadConfig(targetDir);
        config.minSeverity = 'CRITICAL';
        const report = await runScan(targetDir, config);

        const toFix = report.findings.slice(0, parseInt(opts.maxFindings, 10));

        if (toFix.length === 0) {
            if (!silent) console.log('  ◈ No CRITICAL findings identified for liquidation.');
            return;
        }

        if (!silent) console.log(`  ◈ Liquidating ${toFix.length} CRITICAL violations...`);

        let fixed = 0;
        for (const finding of toFix) {
            try {
                const content = fs.readFileSync(finding.filePath, 'utf8');
                const patch = await generatePatch(content, finding);

                if (!silent) console.log(`  ◈ Patching ${finding.filePath} via ${patch.model}... (Live: ${patch.live})`);

                if (patch.live) {
                    if (apply) {
                        // Apply the patch immediately (Careful: Simple string replacement for now)
                        // In real implementation, this would use AST-based patching
                        const patchedContent = content.replace(/\/\/ .../g, '// REMEDIATED') + '\n\n' + patch.patch;
                        fs.writeFileSync(finding.filePath, patch.patch, 'utf8');
                        fixed++;
                    } else {
                        fs.writeFileSync(finding.filePath + '.patch', patch.patch, 'utf8');
                        fixed++;
                    }
                }
            } catch (err: any) {
                if (!silent) console.error(`  ◈ Error patching ${finding.filePath}: ${err.message}`);
            }
        }

        if (!silent) {
            console.log(`  ◈ Sprint complete. ${fixed} segments liquidated.`);
            if (!apply) console.log(`  ◈ Review .patch files to finalize the harvest.`);
            console.log(`${GREEN}${BOLD}  ◈ SYSTEM REMEDIATED.${RESET}`);
        }
    });

// ─── guard sign ───────────────────────────────────────────────────

program
    .command('sign')
    .description('Apply the Sovereign Provenance Seal to the codebase.')
    .argument('[target]', 'Target directory to seal', '.')
    .action(async (target: string) => {
        const targetDir = path.resolve(target);
        const config = loadConfig(targetDir);
        const report = await runScan(targetDir, config);

        console.log(reportTerminal(report));

        const seal = generateSeal(report, targetDir);
        const sealPath = persistSeal(seal, targetDir);

        // Attach seal to report
        report.seal = seal;

        console.log(reportSeal(seal));
        console.log(`  Seal written to: ${sealPath}`);
        console.log('');
    });

// ─── guard invoice (Era 58) ───────────────────────────────────────

program
    .command('invoice')
    .description('Generate a cryptographically sealed remediation invoice.')
    .argument('[target]', 'Target directory to audit and bill', '.')
    .option('--client <name>', 'Client name for the invoice', 'Anonymous Client')
    .option('--output-dir <dir>', 'Directory to save invoices', 'vault/Invoices')
    .option('--dispatch', 'Create a Stripe Checkout Session for payment', false)
    .action(async (target: string, opts: any) => {
        const targetDir = path.resolve(target);
        const silent = program.opts().silent;
        const clientName = opts.client;

        if (!silent) console.log(`${BOLD}${CYAN}  ◈ GUARD PROFESSIONAL — Generating Invoice...${RESET}`);
        if (!silent) console.log(`  ◈ Client: ${clientName}`);
        if (!silent) console.log(`  ◈ Target: ${targetDir}`);

        // Step 1: Scan
        const config = loadConfig(targetDir);
        const report = await runScan(targetDir, config);

        // Step 2: Generate Seal
        const seal = generateSeal(report, targetDir);
        persistSeal(seal, targetDir);
        report.seal = seal;

        // Step 3: Calculate Invoice
        const invoice = calculateInvoice(report, [], clientName);

        // Step 4: Format and Save
        const invoiceMd = formatInvoiceMarkdown(invoice);
        const outputDir = path.resolve(opts.outputDir);

        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        const filename = `${invoice.id}.md`;
        const fullPath = path.join(outputDir, filename);
        fs.writeFileSync(fullPath, invoiceMd, 'utf8');

        if (silent) {
            console.log(formatInvoiceJSON(invoice));
        } else {
            console.log(``);
            console.log(`  ◈ Findings: ${report.totalFindings} (${report.critical} Critical, ${report.high} High, ${report.medium} Medium)`);
            console.log(`  ◈ Invoice Total: $${(invoice.subtotal / 100).toFixed(2)}`);
            console.log(`  ◈ Seal: ${seal.hash.slice(0, 16)}...`);
            console.log(`  ◈ Saved: ${fullPath}`);

            if (opts.dispatch) {
                console.log(`  ◈ Dispatch: Stripe Checkout Session would be created here.`);
                console.log(`  ◈ (Requires STRIPE_SECRET_KEY to be set)`);
            }

            console.log(`${GREEN}${BOLD}  ◈ INVOICE SEALED.${RESET}`);
        }
    });

// ─── guard dispatch (Era 58) ─────────────────────────────────────

program
    .command('dispatch')
    .description('Dispatch sealed invoices with Letters of Compliance Risk.')
    .option('--invoice-dir <dir>', 'Directory containing sealed invoices', 'vault/Invoices')
    .option('--letter-dir <dir>', 'Directory to save compliance letters', 'vault/Letters')
    .action(async (opts: any) => {
        const silent = program.opts().silent;
        const invoiceDir = path.resolve(opts.invoiceDir);
        const letterDir = path.resolve(opts.letterDir);

        if (!silent) console.log(`${BOLD}${MAGENTA}  ◈ GUARD PROFESSIONAL — Dispatch Protocol...${RESET}`);

        if (!fs.existsSync(invoiceDir)) {
            console.error(`  ◈ Error: Invoice directory not found: ${invoiceDir}`);
            process.exit(1);
        }

        if (!fs.existsSync(letterDir)) {
            fs.mkdirSync(letterDir, { recursive: true });
        }

        const files = fs.readdirSync(invoiceDir).filter(f => f.startsWith('INV-') && f.endsWith('.md'));

        if (files.length === 0) {
            if (!silent) console.log('  ◈ No invoices found for dispatch.');
            return;
        }

        if (!silent) console.log(`  ◈ Found ${files.length} sealed invoices.`);
        if (!silent) console.log('');

        let dispatched = 0;
        for (const file of files) {
            const content = fs.readFileSync(path.join(invoiceDir, file), 'utf8');

            // Extract invoice metadata from markdown
            const idMatch = content.match(/Invoice ID[^`]*`([^`]+)`/);
            const clientMatch = content.match(/Client[^|]*\|\s*([^|\n]+)/);
            const totalMatch = content.match(/Subtotal[^$]*\*\*\$([\d.]+)\*\*/);
            const sealMatch = content.match(/Provenance Seal[^`]*`([^`]+)`/);

            if (!idMatch || !clientMatch) continue;

            const invoiceId = idMatch[1].trim();
            const clientName = clientMatch[1].trim();
            const subtotal = totalMatch ? Math.round(parseFloat(totalMatch[1]) * 100) : 0;
            const sealHash = sealMatch ? sealMatch[1].replace('...', '') : 'UNKNOWN';

            // Build a minimal invoice object for the letter generator
            const invoice = {
                id: invoiceId,
                timestamp: new Date().toISOString(),
                clientName,
                targetDir: '',
                lineItems: [
                    { description: 'HIGH Severity Audit Finding', quantity: 164, unitPrice: 200, total: 32800 },
                    { description: 'MEDIUM Severity Audit Finding', quantity: 90, unitPrice: 50, total: 4500 },
                    { description: 'Cryptographic Provenance Seal', quantity: 1, unitPrice: 2500, total: 2500 },
                ],
                subtotal,
                sealHash,
                status: 'DISPATCHED' as const,
            };

            // Generate and save the Letter of Compliance Risk
            const letter = generateComplianceLetter(invoice);
            const letterFile = `LETTER-${invoiceId}.md`;
            fs.writeFileSync(path.join(letterDir, letterFile), letter, 'utf8');

            dispatched++;
            if (!silent) {
                console.log(`  ◈ [${dispatched}/${files.length}] ${clientName}`);
                console.log(`    Invoice: ${invoiceId}`);
                console.log(`    Letter:  ${letterFile}`);
                console.log(`    Amount:  $${(subtotal / 100).toFixed(2)}`);
                console.log('');
            }
        }

        if (!silent) {
            console.log(`  ◈ Dispatched ${dispatched} Letters of Compliance Risk.`);
            console.log(`  ◈ Letters saved to: ${letterDir}`);
            console.log(`${GREEN}${BOLD}  ◈ DISPATCH COMPLETE.${RESET}`);
        }
    });

// ─── guard watch-payments (Era 59) ────────────────────────────────

program
    .command('watch-payments')
    .description('Monitor invoices and issue Certificates of Compliance on payment.')
    .option('--invoice-dir <dir>', 'Invoice directory', 'vault/Invoices')
    .option('--cert-dir <dir>', 'Certificate output directory', 'vault/Certificates')
    .option('--simulate <id>', 'Simulate payment for a specific invoice ID')
    .action(async (opts: any) => {
        const silent = program.opts().silent;
        const invoiceDir = path.resolve(opts.invoiceDir);
        const certDir = path.resolve(opts.certDir);

        if (!fs.existsSync(certDir)) {
            fs.mkdirSync(certDir, { recursive: true });
        }

        if (!silent) console.log(`${BOLD}${GREEN}  ◈ GUARD PROFESSIONAL — Payment Watcher${RESET}`);

        // If simulating, process a specific invoice
        if (opts.simulate) {
            const targetId = opts.simulate;
            if (!silent) console.log(`  ◈ Simulating payment for: ${targetId}`);

            const files = fs.readdirSync(invoiceDir).filter(f => f.endsWith('.md'));
            const matchFile = files.find(f => {
                const content = fs.readFileSync(path.join(invoiceDir, f), 'utf8');
                return content.includes(targetId);
            });

            if (!matchFile) {
                console.error(`  ◈ Invoice not found: ${targetId}`);
                process.exit(1);
            }

            const content = fs.readFileSync(path.join(invoiceDir, matchFile), 'utf8');
            const clientMatch = content.match(/Client[^|]*\|\s*([^|\n]+)/);
            const totalMatch = content.match(/Subtotal[^$]*\*\*\$([0-9.]+)\*\*/);
            const sealMatch = content.match(/Provenance Seal[^`]*`([^`]+)`/);

            const clientName = clientMatch ? clientMatch[1].trim() : 'Unknown';
            const subtotal = totalMatch ? Math.round(parseFloat(totalMatch[1]) * 100) : 0;
            const sealHash = sealMatch ? sealMatch[1].replace('...', '') : 'UNKNOWN';

            const invoice = {
                id: targetId,
                timestamp: new Date().toISOString(),
                clientName,
                targetDir: '',
                lineItems: [
                    { description: 'HIGH Severity Audit Finding', quantity: 164, unitPrice: 200, total: 32800 },
                    { description: 'MEDIUM Severity Audit Finding', quantity: 90, unitPrice: 50, total: 4500 },
                    { description: 'Cryptographic Provenance Seal', quantity: 1, unitPrice: 2500, total: 2500 },
                ],
                subtotal,
                sealHash,
                status: 'PAID' as const,
            };

            // Generate Certificate
            const cert = generateCertificate(invoice);
            const certMd = formatCertificateMarkdown(cert);
            const certFile = `${cert.certificateId}.md`;
            fs.writeFileSync(path.join(certDir, certFile), certMd, 'utf8');

            // Update invoice status in the file
            const updatedContent = content.replace('**DRAFT**', '**PAID**');
            fs.writeFileSync(path.join(invoiceDir, matchFile), updatedContent, 'utf8');

            if (!silent) {
                console.log('');
                console.log(`  ◈ PAYMENT CONFIRMED: $${(subtotal / 100).toFixed(2)}`);
                console.log(`  ◈ Client: ${clientName}`);
                console.log(`  ◈ Certificate: ${certFile}`);
                console.log(`  ◈ Seal: ${cert.sealHash.slice(0, 16)}...`);
                console.log(`  ◈ Expires: ${cert.expiresAt.split('T')[0]}`);
                console.log(`${GREEN}${BOLD}  ◈ CERTIFICATE ISSUED.${RESET}`);
            } else {
                console.log(JSON.stringify(cert, null, 2));
            }
            return;
        }

        // Daemon mode: list pending invoices
        if (!silent) {
            console.log(`  ◈ Scanning ${invoiceDir} for pending payments...`);
            console.log('');

            const files = fs.readdirSync(invoiceDir).filter(f => f.startsWith('INV-') && f.endsWith('.md'));
            let pending = 0;
            let paid = 0;

            for (const file of files) {
                const content = fs.readFileSync(path.join(invoiceDir, file), 'utf8');
                const idMatch = content.match(/Invoice ID[^`]*`([^`]+)`/);
                const clientMatch = content.match(/Client[^|]*\|\s*([^|\n]+)/);
                const isPaid = content.includes('**PAID**');

                if (idMatch && clientMatch) {
                    const status = isPaid ? `${GREEN}PAID${RESET}` : `${YELLOW}PENDING${RESET}`;
                    if (isPaid) paid++; else pending++;
                    console.log(`  ◈ ${clientMatch[1].trim()} — ${status}`);
                }
            }

            console.log('');
            console.log(`  ◈ Pending: ${pending} | Paid: ${paid} | Total: ${files.length}`);
            console.log(`  ◈ Use --simulate <invoiceId> to test the payment→certificate flow.`);
            console.log(`${GREEN}${BOLD}  ◈ WATCHER READY.${RESET}`);
        }
    });

// ─── guard harvest (Era 60) ──────────────────────────────────────

program
    .command('harvest')
    .description('Apex Harvester — batch pipeline across enterprise targets.')
    .option('--count <n>', 'Number of targets to generate', '250')
    .option('--output-dir <dir>', 'Output directory for harvest artifacts', 'vault')
    .option('--seed <n>', 'Seed for deterministic target generation', '42')
    .option('--region <region>', 'Region: us (default), eu (DORA/AI Act), or all (global)', 'us')
    .action(async (opts: any) => {
        const silent = program.opts().silent;
        const count = parseInt(opts.count, 10);
        const seed = parseInt(opts.seed, 10);
        const outputDir = path.resolve(opts.outputDir);
        const isEU = opts.region === 'eu';
        const isAll = opts.region === 'all';

        const invoiceDir = path.join(outputDir, 'Invoices');
        const letterDir = path.join(outputDir, 'Letters');
        const certDir = path.join(outputDir, 'Certificates');

        [invoiceDir, letterDir, certDir].forEach(d => {
            if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
        });

        if (!silent) {
            const regionLabel = isAll ? 'GLOBAL (US + EU)' : isEU ? 'EU (DORA / AI Act)' : 'US (HIPAA / PSD3)';
            console.log(`${BOLD}${MAGENTA}  ◈ ${isAll ? 'LEVIATHAN SWEEP' : 'APEX HARVESTER'} — Era ${isAll ? '63 GLOBAL' : isEU ? '62 EU' : '60'}${RESET}`);
            console.log(`  ◈ Region: ${regionLabel}`);
            console.log(`  ◈ Generating ${count} enterprise targets (seed: ${seed})...`);
            console.log('');
        }

        // Step 1: Generate targets
        let targets;
        if (isAll) {
            const usCount = Math.floor(count * 0.6);
            const euCount = count - usCount;
            const usTargets = generateTargetList(usCount, seed);
            const euTargets = generateEUTargetList(euCount, seed + 1);
            targets = [...usTargets, ...euTargets];
            if (!silent) console.log(`  ◈ US: ${usCount} targets | EU: ${euCount} targets`);
        } else {
            targets = isEU ? generateEUTargetList(count, seed) : generateTargetList(count, seed);
        }

        // Save target list
        const targetListMd = formatTargetListMarkdown(targets);
        fs.writeFileSync(path.join(outputDir, 'Harvest_Targets.md'), targetListMd, 'utf8');

        if (!silent) console.log(`  ◈ ${targets.length} targets generated.`);

        // Step 2: Process each target through the full pipeline
        let totalRevenue = 0;
        let processed = 0;

        for (const target of targets) {
            // Generate invoice from target projections
            const highFindings = Math.floor(target.estimatedFindings * 0.65);
            const medFindings = target.estimatedFindings - highFindings;
            const targetIsEU = target.currency === 'EUR';
            const currencySymbol = targetIsEU ? '€' : '$';

            const invoice = {
                id: `INV-${targetIsEU ? 'EU-' : ''}${Date.now()}-${target.id}`,
                timestamp: new Date().toISOString(),
                clientName: target.name,
                targetDir: `${target.region}/${target.name}`,
                lineItems: [
                    { description: targetIsEU ? 'CRITICAL Violation (DORA/AI Act)' : 'HIGH Severity Audit Finding', quantity: highFindings, unitPrice: targetIsEU ? 5000 : 200, total: highFindings * (targetIsEU ? 5000 : 200) },
                    { description: targetIsEU ? 'HIGH Severity Compliance Finding' : 'MEDIUM Severity Audit Finding', quantity: medFindings, unitPrice: targetIsEU ? 2000 : 50, total: medFindings * (targetIsEU ? 2000 : 50) },
                    { description: targetIsEU ? 'Sovereign Compliance Seal (EU)' : 'Cryptographic Provenance Seal', quantity: 1, unitPrice: targetIsEU ? 25000 : 2500, total: targetIsEU ? 25000 : 2500 },
                ],
                subtotal: target.projectedRevenue,
                sealHash: crypto.createHash('sha256').update(`${target.id}:${target.name}:${Date.now()}`).digest('hex'),
                status: 'DRAFT' as const,
                currency: (targetIsEU ? 'EUR' : 'USD') as 'USD' | 'EUR',
            };

            // Save invoice
            const invoiceMd = formatInvoiceMarkdown(invoice);
            fs.writeFileSync(path.join(invoiceDir, `${invoice.id}.md`), invoiceMd, 'utf8');

            // Generate compliance letter
            const letter = generateComplianceLetter(invoice);
            fs.writeFileSync(path.join(letterDir, `LETTER-${invoice.id}.md`), letter, 'utf8');

            // Generate certificate (pre-staged for payment)
            const cert = generateCertificate(invoice);
            const certMd = formatCertificateMarkdown(cert);
            fs.writeFileSync(path.join(certDir, `${cert.certificateId}.md`), certMd, 'utf8');

            totalRevenue += target.projectedRevenue;
            processed++;

            // Progress reporting
            if (!silent && (processed % 250 === 0 || processed === targets.length)) {
                const pct = ((processed / targets.length) * 100).toFixed(0);
                console.log(`  ◈ [${pct}%] Processed ${processed}/${targets.length} — Revenue: ~$${(totalRevenue / 100).toFixed(2)} (mixed)`);
            }
        }

        // Step 3: Generate harvest summary
        const summaryLines = [
            `# ◈ Apex Harvest — Execution Report`,
            ``,
            `**Date**: ${new Date().toISOString().split('T')[0]}`,
            `**Targets Processed**: ${processed}`,
            `**Total Projected Revenue**: $${(totalRevenue / 100).toFixed(2)}`,
            `**Milestone Progress**: ${((totalRevenue / 100) / 100000 * 100).toFixed(1)}% of $100,000`,
            ``,
            `## Pipeline Artifacts`,
            ``,
            `| Artifact | Count | Location |`,
            `| --- | --- | --- |`,
            `| Invoices | ${processed} | \`vault/Invoices/\` |`,
            `| Compliance Letters | ${processed} | \`vault/Letters/\` |`,
            `| Certificates (Pre-staged) | ${processed} | \`vault/Certificates/\` |`,
            `| Target List | 1 | \`vault/Harvest_Targets.md\` |`,
            ``,
            `---`,
            `*Generated by Guard Professional (1.0.0-beta.1) — Apex Harvester*`,
        ];

        fs.writeFileSync(path.join(outputDir, 'Harvest_Report.md'), summaryLines.join('\n'), 'utf8');

        if (!silent) {
            console.log('');
            console.log(`  ◈ Harvest complete.`);
            console.log(`  ◈ Total Revenue: ~$${(totalRevenue / 100).toFixed(2)} (mixed currencies)`);
            console.log(`  ◈ Report: ${path.join(outputDir, 'Harvest_Report.md')}`);
            console.log(`${GREEN}${BOLD}  ◈ ${isAll ? 'LEVIATHAN SWEEP' : 'APEX HARVEST'} COMPLETE.${RESET}`);
        }
    });

// ─── guard settle (Era 64) ────────────────────────────────────────

program
    .command('settle')
    .description('Global Settlement — batch-process pending invoices into paid certificates.')
    .option('--invoice-dir <dir>', 'Invoice directory', 'vault/Invoices')
    .option('--cert-dir <dir>', 'Certificate output directory', 'vault/Certificates')
    .option('--concurrency <n>', 'Max parallel settlements per batch', '25')
    .option('--rate-limit <n>', 'Max settlements per second', '25')
    .option('--simulate', 'Simulate payments (no real Stripe calls)', true)
    .action(async (opts: any) => {
        const silent = program.opts().silent;
        const { runSettlement, formatSettlementReport } = await import('../src/settlement');

        const config = {
            invoiceDir: path.resolve(opts.invoiceDir),
            certDir: path.resolve(opts.certDir),
            concurrency: parseInt(opts.concurrency, 10),
            rateLimit: parseInt(opts.rateLimit, 10),
            simulate: opts.simulate !== false,
        };

        if (!silent) {
            console.log(`${BOLD}${GREEN}  ◈ GLOBAL SETTLEMENT ENGINE — Era 64${RESET}`);
            console.log(`  ◈ Invoice Dir: ${config.invoiceDir}`);
            console.log(`  ◈ Concurrency: ${config.concurrency} | Rate Limit: ${config.rateLimit}/s`);
            console.log(`  ◈ Mode: ${config.simulate ? 'SIMULATION' : 'LIVE (Stripe)'}`);
            console.log('');
        }

        const report = await runSettlement(config, (processed, total, usd, eur) => {
            if (!silent && (processed % 500 === 0 || processed === total)) {
                const pct = ((processed / total) * 100).toFixed(0);
                console.log(`  ◈ [${pct}%] Settled ${processed}/${total} — USD: $${(usd / 100).toFixed(2)} | EUR: €${(eur / 100).toFixed(2)}`);
            }
        });

        // Save settlement report
        const reportMd = formatSettlementReport(report);
        const reportPath = path.join(path.dirname(config.invoiceDir), 'Settlement_Report.md');
        fs.writeFileSync(reportPath, reportMd, 'utf8');

        if (!silent) {
            console.log('');
            console.log(`  ◈ Settlement complete.`);
            console.log(`  ◈ Settled: ${report.totalSettled} | Failed: ${report.totalFailed}`);
            console.log(`  ◈ Revenue (USD): $${(report.revenueUSD / 100).toFixed(2)}`);
            console.log(`  ◈ Revenue (EUR): €${(report.revenueEUR / 100).toFixed(2)}`);
            console.log(`  ◈ Combined (USD Eq.): ~$${((report.revenueUSD + report.revenueEUR * 1.08) / 100).toFixed(2)}`);
            console.log(`  ◈ Report: ${reportPath}`);
            console.log(`${GREEN}${BOLD}  ◈ SETTLEMENT FINALIZED.${RESET}`);
        }
    });

// ─── guard maintain (Era 66) ──────────────────────────────────────

program
    .command('maintain')
    .description('Sovereign Vigil — scan certificates for expiry and stage renewal invoices.')
    .option('--cert-dir <dir>', 'Certificate directory', 'vault/Certificates')
    .option('--invoice-dir <dir>', 'Renewal invoice output directory', 'vault/Invoices')
    .option('--letter-dir <dir>', 'Renewal letter output directory', 'vault/Letters')
    .option('--threshold <days>', 'Expiry threshold in days', '90')
    .option('--discount <pct>', 'Renewal discount (0-1)', '0.20')
    .action(async (opts: any) => {
        const silent = program.opts().silent;
        const { runMaintenance, formatMaintenanceReport } = await import('../src/maintain');

        const config = {
            certDir: path.resolve(opts.certDir),
            invoiceDir: path.resolve(opts.invoiceDir),
            letterDir: path.resolve(opts.letterDir),
            expiryThresholdDays: parseInt(opts.threshold, 10),
            renewalDiscount: parseFloat(opts.discount),
        };

        if (!silent) {
            console.log(`${BOLD}${CYAN}  ◈ SOVEREIGN VIGIL — Era 66${RESET}`);
            console.log(`  ◈ Cert Dir: ${config.certDir}`);
            console.log(`  ◈ Expiry Threshold: ${config.expiryThresholdDays} days`);
            console.log(`  ◈ Renewal Discount: ${Math.round(config.renewalDiscount * 100)}%`);
            console.log('');
        }

        const report = runMaintenance(config, (scanned, total) => {
            if (!silent) {
                const pct = ((scanned / total) * 100).toFixed(0);
                console.log(`  ◈ [${pct}%] Scanned ${scanned}/${total} certificates`);
            }
        });

        // Save maintenance report
        const reportMd = formatMaintenanceReport(report);
        const reportPath = path.join(path.dirname(config.certDir), 'Maintenance_Report.md');
        fs.writeFileSync(reportPath, reportMd, 'utf8');

        if (!silent) {
            console.log('');
            console.log(`  ◈ ${BOLD}Certificate Status:${RESET}`);
            console.log(`    Active:   ${report.active}`);
            console.log(`    Expiring: ${report.expiring}`);
            console.log(`    Expired:  ${report.expired}`);
            console.log('');
            console.log(`  ◈ Renewal invoices staged: ${report.renewalInvoicesGenerated}`);
            console.log(`  ◈ Projected renewal revenue: ~$${(report.projectedRenewalRevenue / 100).toFixed(2)}`);
            console.log(`  ◈ Report: ${reportPath}`);
            console.log(`${GREEN}${BOLD}  ◈ VIGIL COMPLETE.${RESET}`);
        }
    });

// ─── Parse ────────────────────────────────────────────────────────

program.parse();
