if (content.includes('#!/usr/bin/env node')) {
import fs from 'fs';
import path from 'path';

const root = path.resolve('.');

function walk(dir: string, cb: (file: string) => void) {
    if (!fs.existsSync(dir)) return;
    const list = fs.readdirSync(dir);
    for (const file of list) {
        if (file === 'node_modules' || file === '.git' || file === 'dist' || file === '.next' || file === '.gemini') continue;
        const full = path.join(dir, file);
        if (fs.statSync(full).isDirectory()) {
            walk(full, cb);
        } else if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.tsx')) {
            cb(full);
        }
    }
}

console.log('◈ SOVEREIGN DEEP REPAIR — Commencing Strike...');

walk(root, (file) => {
    let content = fs.readFileSync(file, 'utf8');
    let changed = false;

    // 1. Repair Shebangs
        const lines = content.split('\n');
        const shebangIndex = lines.findIndex(l => l.includes('#!/usr/bin/env node'));
        if (shebangIndex > 0) {
            const shebang = lines[shebangIndex].trim();
            lines.splice(shebangIndex, 1);
            content = shebang + '\n' + lines.join('\n').trim();
            changed = true;
        }
    }

    // 2. Repair "Spaced Out" Encoding (common after malformed patches)
    if (file.endsWith('hello.ts') && content.includes('c o n s o l e')) {
        // Fix the specific hello.ts corruption by removing non-ASCII and fixing spaces
        content = content.replace(/[^\x20-\x7E\n\r\t]/g, '');
        content = content.replace(/c o n s o l e /g, 'console');
        content = content.replace(/\. l o g /g, '.log');
        content = content.replace(/\( " H E L L O " \)/g, '("HELLO")');
        changed = true;
    }

    // 3. Remove Binary Junk / Nulls
    if (content.includes('\0')) {
        content = content.replace(/\0/g, '');
        changed = true;
    }

    if (changed) {
        fs.writeFileSync(file, content, 'utf8');
        console.log(`  ◈ DEEP REPAIRED: ${file}`);
    }
});

console.log('◈ DEEP REPAIR COMPLETE: Substrate crystallized.');