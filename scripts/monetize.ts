import fs from 'fs';
import path from 'path';

const root = path.resolve(__dirname, '..');
const SRC = path.join(root, 'src');
const BIN = path.join(root, 'bin');
const DEST = path.join(root, 'dist-commercial');

if (fs.existsSync(DEST)) {
    fs.rmSync(DEST, { recursive: true });
}
fs.mkdirSync(DEST);

function copyAndSanitize(srcDir: string, destDir: string) {
    if (!fs.existsSync(destDir)) fs.mkdirSync(destDir);
    if (!fs.existsSync(srcDir)) return;

    const list = fs.readdirSync(srcDir);
    for (const file of list) {
        const srcPath = path.join(srcDir, file);
        const destPath = path.join(destDir, file);

        if (fs.statSync(srcPath).isDirectory()) {
            copyAndSanitize(srcPath, destPath);
        } else if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.json')) {
            let content = fs.readFileSync(srcPath, 'utf8');
            // Sanitize Lore & Internal Markers (Case-Insensitive)
            content = content.replace(/Sovereign Guard/gi, 'Guard Professional');
            content = content.replace(/Sovereign/gi, 'Professional');
            content = content.replace(/ERA \d+/gi, 'Commercial Beta 1.0');
            content = content.replace(/Simulation Rot/gi, 'Technical Debt');
            content = content.replace(/Hardened Substrate/gi, 'Compliant Codebase');
            content = content.replace(/Simulation/gi, 'Staging');
            content = content.replace(/SOVEREIGN_PATCH_VERIFIED \(ERA 56\)/g, 'AUDIT_VERIFIED (PRO)');
            content = content.replace(/SOVEREIGN_PATCH_VERIFIED \(ERA 56 FALLBACK\)/g, 'AUDIT_VERIFIED (STATUTORY_FALLBACK)');
            content = content.replace(/Governor/gi, 'Administrator');
            content = content.replace(/Strike/gi, 'Audit');
            content = content.replace(/Liquidate/gi, 'Remediate');
            content = content.replace(/◈/g, '•'); // Decisively professional

            fs.writeFileSync(destPath, content, 'utf8');
        }
    }
}

console.log('• SOVEREIGN MONETIZATION — Crystallizing Commercial Shard...');
copyAndSanitize(SRC, path.join(DEST, 'src'));
copyAndSanitize(BIN, path.join(DEST, 'bin'));

// Copy and sanitize package.json
const pkgPath = path.join(root, 'package.json');
if (fs.existsSync(pkgPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    pkg.name = '@sovereign/guard-pro';
    pkg.version = '1.0.0-beta.1';
    pkg.description = 'Zero-Click HIPAA/PSD3 Automated Remediation Engine.';
    // Remove internal lore-scripts
    if (pkg.scripts) {
        delete pkg.scripts.liquidate;
        delete pkg.scripts.scrub;
        delete pkg.scripts.monetize;
    }
    fs.writeFileSync(path.join(DEST, 'package.json'), JSON.stringify(pkg, null, 2), 'utf8');
}

console.log('• SHARD CRYSTALLIZED: packages/sovereign-guard/dist-commercial/');
