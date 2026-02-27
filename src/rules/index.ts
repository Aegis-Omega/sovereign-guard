import { Rule } from '../types';
import { noSilentCatch } from './no-silent-catch';
import { noAnyType } from './no-any-type';
import { noConsoleLog } from './no-console-log';
import { noHardcodedSecrets } from './no-hardcoded-secrets';
import { noPlaceholderLogic } from './no-placeholder-logic';
import { missingErrorHandling } from './missing-error-handling';
import { complexitySpike } from './complexity-spike';
import { unusedImports } from './unused-imports';
import { todoDebt } from './todo-debt';
import { missingAuditTrail } from './missing-audit-trail';
import { noMathRandom } from './no-math-random';
import { deprecatedApi } from './deprecated-api';
import { noAgentAuthProfile } from './no-agent-auth-profile';
import { hipaa2026Audit } from './hipaa-2026-audit';
import { doraIctRisk } from './dora-ict-risk';
import { euAiAct } from './eu-ai-act';

/**
 * All available rules, ordered by severity.
 */
export const ALL_RULES: Rule[] = [
    hipaa2026Audit,          // CRITICAL
    doraIctRisk,             // CRITICAL (EU DORA)
    euAiAct,                 // CRITICAL (EU AI Act)
    noHardcodedSecrets,     // CRITICAL
    noSilentCatch,          // HIGH
    noAgentAuthProfile,     // HIGH
    missingErrorHandling,   // HIGH
    noMathRandom,           // HIGH
    noAnyType,              // MEDIUM
    noPlaceholderLogic,     // MEDIUM
    missingAuditTrail,      // MEDIUM
    deprecatedApi,          // MEDIUM
    noConsoleLog,           // LOW
    complexitySpike,        // LOW
    unusedImports,          // LOW
    todoDebt,               // LOW
];

export function getRuleById(id: string): Rule | undefined {
    return ALL_RULES.find(r => r.id === id);
}
