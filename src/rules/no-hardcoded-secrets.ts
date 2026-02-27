import { Rule, Finding } from '../types';

/**
 * RULE: no-hardcoded-secrets
 * Detects potential API keys, tokens, passwords, and secrets in source code.
 */
export const noHardcodedSecrets: Rule = {
    id: 'no-hardcoded-secrets',
    name: 'No Hardcoded Secrets',
    severity: 'CRITICAL',
    description: 'API keys, passwords, and tokens must never appear in source code.',

    check(content: string, filePath: string): Finding[] {
        const findings: Finding[] = [];
        const lines = content.split('\n');

        // Skip .env files, config examples, and test fixtures
        if (filePath.endsWith('.env') || filePath.endsWith('.env.example')) return findings;

        const secretPatterns = [
            { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9\-_.]{16,}['"]/i, label: 'API key' },
            { pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/i, label: 'Password' },
            { pattern: /(?:secret|token)\s*[:=]\s*['"][A-Za-z0-9\-_.]{16,}['"]/i, label: 'Secret/Token' },
            { pattern: /(?:aws_access_key_id|aws_secret_access_key)\s*[:=]/i, label: 'AWS credential' },
            { pattern: /sk-[A-Za-z0-9]{20,}/i, label: 'OpenAI API key' },
            { pattern: /AIza[A-Za-z0-9\-_]{35}/, label: 'Google API key' },
            { pattern: /ghp_[A-Za-z0-9]{36}/, label: 'GitHub Personal Access Token' },
            { pattern: /-----BEGIN (?:RSA )?PRIVATE KEY-----/, label: 'Private key' },
        ];

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            // Skip comments
            if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;
            // Skip process.env references (those are safe)
            if (line.includes('process.env')) continue;

            for (const { pattern, label } of secretPatterns) {
                if (pattern.test(line)) {
                    findings.push({
                        ruleId: this.id,
                        ruleName: this.name,
                        severity: this.severity,
                        filePath,
                        line: i + 1,
                        message: `Potential ${label} found hardcoded in source.`,
                        recommendation: 'Move to environment variables (process.env) and add to .gitignore.',
                    });
                    break;
                }
            }
        }

        return findings;
    },
};
