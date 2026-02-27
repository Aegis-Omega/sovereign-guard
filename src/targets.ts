import * as crypto from 'crypto';

/**
 * SOVEREIGN GUARD — Target List Generator (Era 60)
 *
 * Generates a deterministic list of enterprise targets across
 * healthcare and fintech sectors for the Apex Harvest pipeline.
 */

const HEALTHCARE_PREFIXES = [
    'Mercy', 'Providence', 'Heritage', 'Lakeside', 'Summit', 'Valley', 'Pine Ridge',
    'Cedar Creek', 'Riverside', 'Horizon', 'Gateway', 'Prairie', 'Clearwater',
    'Silver Lake', 'Blue Ridge', 'Grandview', 'Oakwood', 'Westfield', 'Northgate',
    'Eastview', 'Ridgeview', 'Sunstone', 'Greenfield', 'Highland', 'Bayview',
];

const HEALTHCARE_SUFFIXES = [
    'Medical Center', 'Health System', 'Hospital', 'Clinical Group', 'Health Network',
    'Medical Associates', 'Health Partners', 'Wellness Center', 'Care Network',
    'Regional Hospital',
];

const FINTECH_PREFIXES = [
    'Apex', 'Pinnacle', 'Meridian', 'Summit', 'Keystone', 'Vanguard', 'Sterling',
    'Atlas', 'Nexus', 'Beacon', 'Core', 'Quantum', 'Vertex', 'Nova', 'Catalyst',
    'Prism', 'Vector', 'Zenith', 'Forge', 'Citadel',
];

const FINTECH_SUFFIXES = [
    'Financial Group', 'Capital Partners', 'Bancshares', 'Financial Services',
    'Payment Solutions', 'Digital Banking', 'Credit Union', 'Wealth Management',
    'Asset Group', 'Trust Company',
];

const REGIONS = [
    'Missouri', 'Illinois', 'Kansas', 'Iowa', 'Nebraska', 'Colorado', 'Ohio',
    'Indiana', 'Kentucky', 'Tennessee', 'Oklahoma', 'Arkansas', 'Wisconsin',
    'Minnesota', 'Michigan',
];

export interface HarvestTarget {
    id: string;
    name: string;
    sector: 'Healthcare' | 'FinTech' | 'EU-FinTech' | 'EU-AI';
    region: string;
    complianceVector: string;
    estimatedFindings: number;
    projectedRevenue: number; // smallest currency unit
    currency?: 'USD' | 'EUR';
}

// ─── EU Name Pools ─────────────────────────────────────────────

const EU_FINTECH_PREFIXES = [
    'Deutsche', 'Société', 'Raiffeisen', 'Nordea', 'ING', 'ABN AMRO',
    'Commerzbank', 'UniCredit', 'Intesa', 'Santander', 'KBC', 'Erste',
    'Handelsbanken', 'Danske', 'Swedbank', 'CaixaBank', 'Belfius',
    'OP Financial', 'Mediobanca', 'Bank of Ireland', 'Bankinter',
    'Bunq', 'N26', 'Revolut', 'Wise',
];

const EU_FINTECH_SUFFIXES = [
    'Banking Group', 'Financial Services', 'Capital Markets',
    'Payment Solutions', 'Digital Finance', 'Wealth Platform',
    'Investment Services', 'Securities', 'Asset Management',
    'Treasury Services',
];

const EU_AI_PREFIXES = [
    'DeepTech', 'Algorithmica', 'NeuralForge', 'CogniSys', 'Synthesia',
    'Aleph Alpha', 'Mistral', 'Helsing', 'Tractable', 'Darktrace',
    'Oxbotica', 'Wayve', 'BioNTech AI', 'Siemens AI', 'Bosch AI',
    'SAP Intelligence', 'ThoughtWorks EU', 'DataRobot EU', 'Palantir EU',
    'Celonis', 'Personio', 'UiPath EU', 'Graphcore', 'Onfido',
    'Eigen Technologies',
];

const EU_AI_SUFFIXES = [
    'AI Systems', 'Intelligence Platform', 'Machine Learning Group',
    'Autonomous Solutions', 'Neural Networks', 'Cognitive Services',
    'AI Lab', 'Deep Learning Division', 'Predictive Analytics',
    'Computer Vision Unit',
];

const EU_REGIONS = [
    'Frankfurt', 'Amsterdam', 'Paris', 'Dublin', 'Warsaw', 'Milan',
    'Madrid', 'Stockholm', 'Copenhagen', 'Helsinki', 'Vienna',
    'Brussels', 'Luxembourg', 'Lisbon', 'Prague', 'Zurich',
    'Munich', 'Berlin', 'Barcelona', 'Rome',
];

export function generateTargetList(count: number, seed: number = 42): HarvestTarget[] {
    const targets: HarvestTarget[] = [];
    // Simple seeded random for determinism
    let state = seed;
    function nextRand(): number {
        state = (state * 1103515245 + 12345) & 0x7fffffff;
        return state / 0x7fffffff;
    }

    for (let i = 0; i < count; i++) {
        const isHealthcare = nextRand() > 0.35; // 65% healthcare
        const prefixes = isHealthcare ? HEALTHCARE_PREFIXES : FINTECH_PREFIXES;
        const suffixes = isHealthcare ? HEALTHCARE_SUFFIXES : FINTECH_SUFFIXES;
        const prefix = prefixes[Math.floor(nextRand() * prefixes.length)];
        const suffix = suffixes[Math.floor(nextRand() * suffixes.length)];
        const region = REGIONS[Math.floor(nextRand() * REGIONS.length)];
        const name = `${prefix} ${suffix}`;
        const sector = isHealthcare ? 'Healthcare' : 'FinTech';
        const complianceVector = isHealthcare
            ? 'HIPAA-2026 (45 CFR § 164.312)'
            : 'PSD3 (SCA/API Transparency)';
        const highFindings = Math.floor(100 + nextRand() * 180);
        const medFindings = Math.floor(40 + nextRand() * 80);
        const estimatedFindings = highFindings + medFindings;
        const projectedRevenue = (highFindings * 200) + (medFindings * 50) + 2500;
        targets.push({
            id: `TGT-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
            name,
            sector,
            region,
            complianceVector,
            estimatedFindings,
            projectedRevenue,
        });
    }
    return targets;
}

export function formatTargetListMarkdown(targets: HarvestTarget[]): string {
    const totalRevenue = targets.reduce((s, t) => s + t.projectedRevenue, 0);
    const currency = targets[0]?.currency || 'USD';
    const sym = currency === 'EUR' ? '€' : '$';

    // Count sectors dynamically
    const sectorCounts: Record<string, number> = {};
    for (const t of targets) {
        sectorCounts[t.sector] = (sectorCounts[t.sector] || 0) + 1;
    }
    const sectorSummary = Object.entries(sectorCounts).map(([s, c]) => `${s} (${c})`).join(' | ');

    const lines: string[] = [
        `# ◈ Guard Professional — Harvest Target List`,
        ``,
        `**Generated**: ${new Date().toISOString().split('T')[0]}`,
        `**Targets**: ${targets.length}`,
        `**Currency**: ${currency}`,
        `**Projected Revenue**: ${sym}${(totalRevenue / 100).toFixed(2)}`,
        `**Sectors**: ${sectorSummary}`,
        ``,
        `---`,
        ``,
        `| # | Target | Sector | Region | Findings | Revenue |`,
        `| --- | --- | --- | --- | ---: | ---: |`,
    ];

    targets.forEach((t, i) => {
        lines.push(`| ${i + 1} | ${t.name} | ${t.sector} | ${t.region} | ${t.estimatedFindings} | ${sym}${(t.projectedRevenue / 100).toFixed(2)} |`);
    });

    lines.push(`| | **TOTAL** | | | | **${sym}${(totalRevenue / 100).toFixed(2)}** |`);
    lines.push(``);
    lines.push(`---`);
    lines.push(`*Generated by Guard Professional (1.0.0-beta.1)*`);

    return lines.join('\n');
}

// ─── EU Target Generator ──────────────────────────────────────────

export function generateEUTargetList(count: number, seed: number = 99): HarvestTarget[] {
    const targets: HarvestTarget[] = [];
    let state = seed;
    function nextRand(): number {
        state = (state * 1103515245 + 12345) & 0x7fffffff;
        return state / 0x7fffffff;
    }

    for (let i = 0; i < count; i++) {
        const isFinTech = nextRand() > 0.40; // 60% FinTech, 40% AI
        const prefixes = isFinTech ? EU_FINTECH_PREFIXES : EU_AI_PREFIXES;
        const suffixes = isFinTech ? EU_FINTECH_SUFFIXES : EU_AI_SUFFIXES;
        const prefix = prefixes[Math.floor(nextRand() * prefixes.length)];
        const suffix = suffixes[Math.floor(nextRand() * suffixes.length)];
        const region = EU_REGIONS[Math.floor(nextRand() * EU_REGIONS.length)];
        const name = `${prefix} ${suffix}`;
        const sector: 'EU-FinTech' | 'EU-AI' = isFinTech ? 'EU-FinTech' : 'EU-AI';
        const complianceVector = isFinTech
            ? 'DORA (EU 2022/2554, Art. 5-44)'
            : 'EU AI Act (2024/1689, Title III)';

        // EU pricing: higher per-finding revenue
        const critFindings = Math.floor(3 + nextRand() * 8);   // 3-10 CRITICAL
        const highFindings = Math.floor(20 + nextRand() * 60);  // 20-80 HIGH
        const medFindings = Math.floor(10 + nextRand() * 40);   // 10-50 MEDIUM
        const estimatedFindings = critFindings + highFindings + medFindings;
        // EUR cents: 5000/crit + 2000/high + 500/med + 25000 seal
        const projectedRevenue = (critFindings * 5000) + (highFindings * 2000) + (medFindings * 500) + 25000;

        targets.push({
            id: `TGT-EU-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
            name,
            sector,
            region,
            complianceVector,
            estimatedFindings,
            projectedRevenue,
            currency: 'EUR',
        });
    }
    return targets;
}
