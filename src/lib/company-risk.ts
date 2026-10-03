// "My company" risk model — closed-form, deterministic. Formulas documented in company-risk-model_v6.md.

export type CompanyInputs = {
  vendorVulns: number; // N_v: exploited vendor vulns per year in your stack (fully vendor-built)
  patchDays: number; // D_p: median days to patch
  neverPatched: number; // u: share of affected systems never patched
  appsec: number; // 0 none · 1 basic · 2 AI-assisted · 3 AI-first, continuous
  bountyK: number; // bug bounty budget, $k per year
  hardening: number; // 0–4
  soc: number; // 0–3
  governance: number; // 0–3
  inHouse: number; // f: share built in-house (with AI)
  threat: number; // m: attacker AI multiplier on your own code
  vendorGrowth: number; // k_v: growth in exploitation of vendor vulnerabilities
};

// Observed: CVEs published 2023–2025 that are in CISA KEV (snapshot 30 Sep 2026), n = 522.
export const VENDOR_ZERO_DAY_SHARE = 0.31; // z_v: listed in KEV on/before publication day. 19% for all KEV entries added since 2022.
export const NDAY_MEDIAN_DAYS = 36; // median n-day delay to KEV listing (n = 358)
export const NDAY_BINS: readonly (readonly [number, number])[] = [[3, 0.293], [12, 0.087], [21, 0.084], [39.5, 0.123], [84, 0.059], [131, 0.131], [259, 0.123], [626, 0.101]];
export const MEDIAN_DAYS_TO_KEV = NDAY_MEDIAN_DAYS;
export const OWN_BASE_ATTACKER_WIN = 0.35; // z_o: baseline discovery races attackers win in own code (assumption)
export const OWN_BUGS_PER_YEAR = 1.5; // N_o: bugs/year an attacker eventually finds in a fully in-house stack at m = 1
export const APPSEC_FIND_RATE = [0, 0.5, 1.5, 3]; // relative to today's attacker (m = 1)
export const BOUNTY_MAX_RATE = 2;
export const BOUNTY_HALF_K = 250;
export const EXPOSURE = 0.05; // e: share of exploited stack bugs reachable at your company (calibration assumption)
export const HARDENING_PASS = [1, 0.5, 0.24, 0.12, 0.06]; // relative: "halves per level" is an assumption
export const SOC_CONTAIN = [0, 0.4, 0.65, 0.85];
export const GOV_LARGE = [0.5, 0.35, 0.2, 0.1];
export const HARDENING_SIZE = [1, 0.85, 0.7, 0.55, 0.4];
export const VULN_SHARE_RANGE = [0.12, 0.31] as const; // s: share of all breaches that start with a vulnerability

export type ChannelResult = { lightning: number; raceP: number; // vendor: P(attacker wins); own: relative risk R_own vs today
  winsRace: number; reached: number; pastHardening: number; breaches: number };
export type CompanyResult = {
  vendor: ChannelResult;
  own: ChannelResult;
  lambda: number;
  pYear: number;
  p5: number;
  largeShare: number;
  lambdaLarge: number;
  pLarge5: number;
  allCause: [number, number];
  vulnerabilityShare: [number, number];
  lambdaBaseline: number;
};

const idx = (arr: readonly number[], i: number) => arr[Math.max(0, Math.min(arr.length - 1, Math.round(i)))] ?? 0;

// Attacker-AI exponents (assumptions): m acts on every attack step.
// Scenario elasticities (not measured).
export const M_EXP_COVERAGE = 0.5; // L_own = N_o·f·m^0.5
export const M_EXP_EXPLOIT = 0.5; // n-day delays / m^0.5
export const M_EXP_HARDENING = 0.3; // h = min(1, e·h_H·m^0.3)
export const M_EXP_SOC = 0.3; // c_eff = c_S / m^0.3

export type ModelParams = { zv: number; u?: number; e: number; expCoverage: number; expExploit: number; expHardening: number; expSoc: number };
export const CENTRAL_PARAMS: ModelParams = { zv: VENDOR_ZERO_DAY_SHARE, e: EXPOSURE, expCoverage: M_EXP_COVERAGE, expExploit: M_EXP_EXPLOIT, expHardening: M_EXP_HARDENING, expSoc: M_EXP_SOC };
// Uncertainty variants keep the user's u (never-patched slider); they vary only z_v, e and the elasticities.
export const LOW_PARAMS: ModelParams = { zv: 0.19, e: 0.025, expCoverage: 0, expExploit: 0, expHardening: 0, expSoc: 0 };
export const HIGH_PARAMS: ModelParams = { zv: 0.31, e: 0.1, expCoverage: 1, expExploit: 1, expHardening: 0.5, expSoc: 0.5 };

/** F: share of n-day vulns you patch only after the KEV listing (patch time exponential with median D_p). */
export function lateShare(patchDays: number, m = 1, expExploit = M_EXP_EXPLOIT) {
  const speed = Math.pow(m, expExploit);
  return NDAY_BINS.reduce((sum, [days, share]) => sum + share * Math.pow(0.5, days / speed / patchDays), 0);
}

export function vendorRace(patchDays: number, neverPatched: number, m = 1, zv = VENDOR_ZERO_DAY_SHARE, expExploit = M_EXP_EXPLOIT) {
  const F = lateShare(patchDays, m, expExploit);
  return zv + (1 - zv) * (neverPatched + (1 - neverPatched) * F);
}

export function riskRange(c: CompanyInputs) {
  const lo = computeRisk(c, LOW_PARAMS), hi = computeRisk(c, HIGH_PARAMS);
  return { p5: [Math.min(lo.p5, hi.p5), Math.max(lo.p5, hi.p5)] as [number, number] };
}

export function computeRisk(c: CompanyInputs, P: ModelParams = CENTRAL_PARAMS): CompanyResult {
  const m = Math.max(1, c.threat ?? 1);
  const u = P.u ?? c.neverPatched;
  const pass = Math.min(1, P.e * idx(HARDENING_PASS, c.hardening) * Math.pow(m, P.expHardening));
  const contain = idx(SOC_CONTAIN, c.soc) / Math.pow(m, P.expSoc);
  const escape = 1 - contain;
  const pass0 = P.e * idx(HARDENING_PASS, c.hardening);
  const escape0 = 1 - idx(SOC_CONTAIN, c.soc);
  // Keep hot-reloaded sessions from older model versions valid when a new input is introduced.
  const vendorGrowth = c.vendorGrowth ?? DEFAULT_COMPANY.vendorGrowth;

  // Preserve the calibrated combined pass probability, including high-AI scenarios.
  const reach = Math.max(P.e, pass);
  const vendor = channel(c.vendorVulns * (1 - c.inHouse) * vendorGrowth, vendorRace(c.patchDays, u, m, P.zv, P.expExploit), pass, escape, reach);

  const defend = idx(APPSEC_FIND_RATE, c.appsec) + BOUNTY_MAX_RATE * c.bountyK / (c.bountyK + BOUNTY_HALF_K);
  // Race 2 (article formula): attacker share of discovery races and the zero-day window shrink with defender speed D.
  const D = 1 + defend;
  const ownRiskMultiplier = (threat: number) => {
    const attackerWin = threat * OWN_BASE_ATTACKER_WIN / (threat * OWN_BASE_ATTACKER_WIN + D * (1 - OWN_BASE_ATTACKER_WIN));
    return attackerWin / OWN_BASE_ATTACKER_WIN / D;
  };
  const rOwn = ownRiskMultiplier(c.threat);
  const own = channel(OWN_BUGS_PER_YEAR * c.inHouse * Math.pow(m, P.expCoverage), rOwn, pass, escape, reach);

  const lambda = vendor.breaches + own.breaches;
  // All-cause calibration holds today's vulnerability environment fixed (k_v = 1, m = 1).
  const baselineVendor = channel(c.vendorVulns * (1 - c.inHouse), vendorRace(c.patchDays, u, 1, P.zv), pass0, escape0);
  const baselineOwn = channel(OWN_BUGS_PER_YEAR * c.inHouse, ownRiskMultiplier(1), pass0, escape0);
  const lambdaBaseline = baselineVendor.breaches + baselineOwn.breaches;
  const allCauseValues = VULN_SHARE_RANGE.map((s) => lambda + lambdaBaseline * (1 - s) / s);
  const allCause = [Math.min(...allCauseValues), Math.max(...allCauseValues)] as [number, number];
  const vulnerabilityShareValues = allCause.map((total) => lambda / total);
  const vulnerabilityShare = [Math.min(...vulnerabilityShareValues), Math.max(...vulnerabilityShareValues)] as [number, number];
  const largeShare = idx(GOV_LARGE, c.governance) * (1 - 0.5 * contain) * idx(HARDENING_SIZE, c.hardening);
  const lambdaLarge = lambda * largeShare;
  return {
    vendor, own, lambda,
    pYear: 1 - Math.exp(-lambda),
    p5: 1 - Math.exp(-5 * lambda),
    largeShare, lambdaLarge,
    pLarge5: 1 - Math.exp(-5 * lambdaLarge),
    allCause, vulnerabilityShare, lambdaBaseline,
  };
}

function channel(lightning: number, raceP: number, pass: number, escape: number, reach = EXPOSURE): ChannelResult {
  const winsRace = lightning * raceP;
  const pastHardening = winsRace * pass;
  return { lightning, raceP, winsRace, reached: winsRace * reach, pastHardening, breaches: pastHardening * escape };
}

export const DEFAULT_COMPANY: CompanyInputs = { vendorVulns: 6, patchDays: 43, neverPatched: 0.1, appsec: 1, bountyK: 0, hardening: 1, soc: 1, governance: 1, inHouse: 0.4, threat: 1, vendorGrowth: 1 };
