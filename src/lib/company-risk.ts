// "My company" risk model — closed-form, deterministic. Formulas documented in company-risk-model.md.

export type CompanyInputs = {
  patchDays: number; // median days to patch a vendor vulnerability
  appsec: number; // 0 none · 1 basic SAST/DAST · 2 AI-assisted · 3 AI-first, continuous
  bountyK: number; // bug bounty budget, $k per year (0 = none)
  hardening: number; // 0–4 isolation & hardening level
  soc: number; // 0 none · 1 business hours · 2 24/7 MDR · 3 mature 24/7 + hunting
  governance: number; // 0 none · 1 basic · 2 minimised & encrypted · 3 strict minimisation
  inHouse: number; // 0–1 share of software you build yourself (vs vendors)
  threat: number; // exploit growth multiplier from AI, ×1–×6
};

export const MEDIAN_DAYS_TO_EXPLOIT = 14; // article: about half of KEV entries within two weeks
export const VENDOR_EXPLOITED_PER_YEAR = 2; // exploited vendor vulns touching a fully vendor-built company (assumption)
export const OWN_BUGS_PER_YEAR = 1.5; // exploitable bugs a fully in-house company ships per year (assumption)
export const APPSEC_FIND_RATE = [0, 0.5, 1.5, 3];
export const BOUNTY_MAX_RATE = 2;
export const BOUNTY_HALF_K = 250;
export const HARDENING_PASS = [0.5, 0.35, 0.22, 0.12, 0.06];
export const SOC_CONTAIN = [0, 0.3, 0.55, 0.75];
export const GOV_LARGE = [0.5, 0.35, 0.2, 0.1];

export type ChannelResult = { lightning: number; winsRace: number; pastHardening: number; breaches: number; raceP: number };
export type CompanyResult = {
  vendor: ChannelResult;
  own: ChannelResult;
  lambda: number;
  pYear: number;
  p5: number;
  lambdaLarge: number;
  pLarge5: number;
};

const idx = (arr: number[], i: number) => arr[Math.max(0, Math.min(arr.length - 1, Math.round(i)))] ?? 0;

export function computeRisk(c: CompanyInputs): CompanyResult {
  const pass = idx(HARDENING_PASS, c.hardening);
  const escape = 1 - idx(SOC_CONTAIN, c.soc);

  // Race 1: vendor vulnerability — your patch vs the attacker's exploit (exponential race, medians).
  const vLightning = VENDOR_EXPLOITED_PER_YEAR * (1 - c.inHouse) * c.threat;
  const vRace = c.patchDays / (c.patchDays + MEDIAN_DAYS_TO_EXPLOIT);
  const vendor = channel(vLightning, vRace, pass, escape);

  // Race 2: your own bug — attackers find it vs your AppSec + bug bounty find it first.
  const defend = idx(APPSEC_FIND_RATE, c.appsec) + BOUNTY_MAX_RATE * c.bountyK / (c.bountyK + BOUNTY_HALF_K);
  const oLightning = OWN_BUGS_PER_YEAR * c.inHouse;
  const oRace = c.threat / (c.threat + defend);
  const own = channel(oLightning, oRace, pass, escape);

  const lambda = vendor.breaches + own.breaches;
  const lambdaLarge = lambda * idx(GOV_LARGE, c.governance);
  return {
    vendor, own, lambda,
    pYear: 1 - Math.exp(-lambda),
    p5: 1 - Math.exp(-5 * lambda),
    lambdaLarge,
    pLarge5: 1 - Math.exp(-5 * lambdaLarge),
  };
}

function channel(lightning: number, raceP: number, pass: number, escape: number): ChannelResult {
  const winsRace = lightning * raceP;
  const pastHardening = winsRace * pass;
  return { lightning, raceP, winsRace, pastHardening, breaches: pastHardening * escape };
}

export const DEFAULT_COMPANY: CompanyInputs = { patchDays: 43, appsec: 1, bountyK: 0, hardening: 1, soc: 1, governance: 1, inHouse: 0.4, threat: 1 };
