// "My company" risk model — closed-form, deterministic. Formulas documented in company-risk-model_v4.md.

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

export const MEDIAN_DAYS_TO_KEV = 14; // D_e: median days to being added to CISA's list (upper bound on exploitation)
export const VENDOR_ZERO_DAY_SHARE = 0.19; // z_v: vendor vulns exploited before a patch exists (measured)
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
  winsRace: number; pastHardening: number; breaches: number };
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
};

const idx = (arr: readonly number[], i: number) => arr[Math.max(0, Math.min(arr.length - 1, Math.round(i)))] ?? 0;

export function vendorRace(patchDays: number, neverPatched: number) {
  const race = patchDays / (patchDays + MEDIAN_DAYS_TO_KEV);
  return VENDOR_ZERO_DAY_SHARE + (1 - VENDOR_ZERO_DAY_SHARE) * (neverPatched + (1 - neverPatched) * race);
}

export function computeRisk(c: CompanyInputs): CompanyResult {
  const pass = EXPOSURE * idx(HARDENING_PASS, c.hardening);
  const contain = idx(SOC_CONTAIN, c.soc);
  const escape = 1 - contain;
  // Keep hot-reloaded sessions from older model versions valid when a new input is introduced.
  const vendorGrowth = c.vendorGrowth ?? DEFAULT_COMPANY.vendorGrowth;

  const vendor = channel(c.vendorVulns * (1 - c.inHouse) * vendorGrowth, vendorRace(c.patchDays, c.neverPatched), pass, escape);

  const defend = idx(APPSEC_FIND_RATE, c.appsec) + BOUNTY_MAX_RATE * c.bountyK / (c.bountyK + BOUNTY_HALF_K);
  // Race 2 (article formula): attacker share of discovery races and the zero-day window shrink with defender speed D.
  const D = 1 + defend;
  const sOwn = c.threat * OWN_BASE_ATTACKER_WIN / (c.threat * OWN_BASE_ATTACKER_WIN + D * (1 - OWN_BASE_ATTACKER_WIN));
  const rOwn = sOwn / OWN_BASE_ATTACKER_WIN / D;
  const own = channel(OWN_BUGS_PER_YEAR * c.inHouse, rOwn, pass, escape);

  const lambda = vendor.breaches + own.breaches;
  const largeShare = idx(GOV_LARGE, c.governance) * (1 - 0.5 * contain) * idx(HARDENING_SIZE, c.hardening);
  const lambdaLarge = lambda * largeShare;
  return {
    vendor, own, lambda,
    pYear: 1 - Math.exp(-lambda),
    p5: 1 - Math.exp(-5 * lambda),
    largeShare, lambdaLarge,
    pLarge5: 1 - Math.exp(-5 * lambdaLarge),
    allCause: [lambda / VULN_SHARE_RANGE[1], lambda / VULN_SHARE_RANGE[0]],
  };
}

function channel(lightning: number, raceP: number, pass: number, escape: number): ChannelResult {
  const winsRace = lightning * raceP;
  const pastHardening = winsRace * pass;
  return { lightning, raceP, winsRace, pastHardening, breaches: pastHardening * escape };
}

export const DEFAULT_COMPANY: CompanyInputs = { vendorVulns: 6, patchDays: 43, neverPatched: 0.1, appsec: 1, bountyK: 0, hardening: 1, soc: 1, governance: 1, inHouse: 0.4, threat: 1, vendorGrowth: 1 };
