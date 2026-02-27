import { execSync } from 'child_process';
import * as path from 'path';

/**
 * SOVEREIGN GUARD — Liquidation Strike (Era 56)
 * 
 * Batch-resolves the 132 CRITICAL violations in the substrate.
 */

const TARGET_DIR = path.resolve('.');
const GUARD_BIN = 'npx tsx packages/sovereign-guard/bin/guard.ts';

async function runSprint() {
    console.log('◈ SOVEREIGN LIQUIDATION — Commencing Strike...');

    // Step 1: Liquidate CRITICALs in the core agent-app
    try {
        console.log('◈ PHASE 1: Liquidating agent-app core...');
        execSync(`${GUARD_BIN} remediate agent-app --apply`, { stdio: 'inherit' });
    } catch (err) {
        console.error('◈ STRIKE PARTIALLY FAILED:', err);
    }

    // Step 2: Finality Check
    console.log('◈ PHASE 2: Verifying substrate finality...');
    try {
        execSync(`${GUARD_BIN} scan agent-app --min-severity CRITICAL --silent`, { stdio: 'inherit' });
        console.log('◈ MISSION SUCCESS: Substrate finality reached.');
    } catch {
        console.log('◈ MISSION CONTINUE: Residual debt remaining. Initiating Cycle 2...');
    }
}

runSprint().catch(console.error);
