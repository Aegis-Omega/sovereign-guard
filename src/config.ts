import * as fs from 'fs';
import * as path from 'path';
import { GuardConfig, DEFAULT_CONFIG } from './types';

/**
 * Load configuration from .guardrc.json in the target directory.
 * Falls back to defaults if no config file is found.
 */
export function loadConfig(targetDir: string): GuardConfig {
    const configPath = path.join(targetDir, '.guardrc.json');

    if (!fs.existsSync(configPath)) {
        return { ...DEFAULT_CONFIG };
    }

    try {
        const raw = fs.readFileSync(configPath, 'utf8');
        const userConfig = JSON.parse(raw) as Partial<GuardConfig>;

        return {
            include: userConfig.include ?? DEFAULT_CONFIG.include,
            exclude: userConfig.exclude ?? DEFAULT_CONFIG.exclude,
            disableRules: userConfig.disableRules ?? DEFAULT_CONFIG.disableRules,
            minSeverity: userConfig.minSeverity ?? DEFAULT_CONFIG.minSeverity,
            maxFiles: userConfig.maxFiles ?? DEFAULT_CONFIG.maxFiles,
        };
    } catch (err: unknown) {
        console.warn(`⚠ Failed to parse .guardrc.json: ${err instanceof Error ? err.message : err}`);
        return { ...DEFAULT_CONFIG };
    }
}
