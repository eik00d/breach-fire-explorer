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
  threat: number; // master AI: all four amplifiers follow it unless advanced mode is on
  advancedAI?: boolean;
  aiVuln?: number;
  aiCred?: number;
  aiPhish?: number;
  aiEntry?: number;
  vendorGrowth: number; // k_v: growth in exploitation of vendor vulnerabilities
  size?: CompanySize; // calibrates e to published breach frequency by company size
  smallBreachShare?: number; // scenario: share below the 500-person reporting line
  identity?: number; // 0 none · 1 passwords + SMS (default) · 2 MFA everywhere · 3 phishing-resistant MFA
  emailFiltering?: number; // 0 basic · 1 standard (default) · 2 advanced sandboxing
  training?: number; // 0 none · 1 annual (default) · 2 regular simulations
  edr?: number; // 0 none · 1 antivirus (default) · 2 EDR · 3 automated blocking
  deviceManagement?: number; // shared: 0 unmanaged · 1 BYOD with MDM (default) · 2 managed only
  credentialExposure?: number; // scenario: credential attempts multiplier, 0.5–3 (default 1)
  phishingPressure?: number; // scenario: phishing lures multiplier, 0.5–3 (default 1)
  ownFocus?: number; // scenario: attacker focus on your own code, ×1–×5 (default 1)
  ownFocusElasticity?: number; // scenario: L_own ∝ m^elasticity, 0–1 (default 0.5; advanced AI mode only)
  vendorsHolding?: number; // scenario: vendors holding your data (5–500); default by size
  supplierShare?: number; // scenario: supplier share of publicly known events at defaults (0.17–0.34), carved from the residual
  supplierSecurity?: number; // 0 none · 1 questionnaires (default) · 2 SaaS access/token hygiene & data minimisation
};

// Verizon DBIR 2026: select initial access vectors in non-Error, non-Misuse breaches (1 Nov 2024 – 31 Oct 2025).
// The residual includes other entry routes, errors and insider misuse to match all-event IRIS totals.
// Other channels are calibrated so that
// at default settings λ_c = λ_vuln × share_c / share_vuln.
export const CHANNEL_SHARE = { vuln: 0.31, cred: 0.13, phish: 0.16, pretext: 0.06, other: 0.09, supplier: 0.25 } as const;
export type ChannelKey = keyof typeof CHANNEL_SHARE;
export function aiAmplifiers(c: CompanyInputs) {
  const master = Math.max(1, c.threat ?? 1);
  const resolve = (value?: number) => c.advancedAI ? Math.max(1, value ?? master) : master;
  return { vuln: resolve(c.aiVuln), cred: resolve(c.aiCred), phish: resolve(c.aiPhish), entry: resolve(c.aiEntry) };
}
export const AI_SCENARIOS = [
  { id: "today", label: "Today", master: 1, growth: 1, phishing: 1 },
  { id: "vulnpocalypse", label: "Vulnpocalypse only", master: 1, growth: 2.2, phishing: 1 },
  { id: "phishing", label: "AI phishing only", master: 1, growth: 1, phishing: 6 },
  { id: "everything", label: "Everything at once", master: 6, growth: 2.2, phishing: 6 },
] as const;
export function applyAIScenario(c: CompanyInputs, scenario: typeof AI_SCENARIOS[number]): CompanyInputs {
  // Change only AI and exploitation growth; preserve the user's current company and defences.
  return { ...c, threat: scenario.master, vendorGrowth: scenario.growth, advancedAI: scenario.id === "phishing", aiVuln: scenario.master, aiCred: scenario.master, aiPhish: scenario.phishing, aiEntry: scenario.master };
}
export function isAIScenario(c: CompanyInputs, scenario: typeof AI_SCENARIOS[number]) {
  const a = aiAmplifiers(c);
  const eq = (x: number, y: number) => Math.abs(x - y) < 1e-9;
  return eq(c.vendorGrowth ?? 1, scenario.growth) && eq(a.vuln, scenario.master) && eq(a.cred, scenario.master) && eq(a.phish, scenario.phishing) && eq(a.entry, scenario.master);
}
// Scenario assumptions: multipliers relative to the default level.
export const IDENTITY_CRED = [1.6, 1, 0.4, 0.15];
export const IDENTITY_PRETEXT = [1.2, 1, 0.8, 0.6];
export const SUPPLIER_SECURITY = [1.3, 1, 0.6]; // scenario assumption, not a measured DBIR split
export const RESIDUAL_POOL = 0.34; // residual + supplier together
export const SUPPLIER_SHARE_RANGE = [0.17, 0.34] as const;
export const M_EXP_SUPPLIER = 0.3; // scenario elasticity, as for credentials
export const VENDORS_BY_SIZE: Record<CompanySize, number> = { small: 15, mid: 60, large: 300 }; // scenario assumption
export const VENDORS_RANGE = [5, 500] as const;
export const VENDOR_INCIDENT_RATE = 0.093; // IRIS typical-organisation annual rate, applied to each vendor
export const VENDOR_IN_SCOPE = 0.15; // share of vendor incidents that involve your data (assumption)
export const SUPPLIER_TAKEN_SHARE = 0.30; // scenario assumption; supplier security scales this step
export const RESIDUAL_EVENTS_MID = 1.0; // misdirected data, misconfigured storage, insider access, other routes per year at mid
export const SUPPLIER_LARGE_MULTIPLIER = 1.9; // HHS 2021–2026: 27% vs 14% reach 100,000+ people
export const IDENTITY_PHISH = [1.3, 1, 0.7, 0.35];
export const EMAIL_FILTERING = [1.3, 1, 0.8];
export const TRAINING_PHISH = [1.05, 1, 0.92];
export const EDR_EFFECTIVENESS = [0, 0.2, 0.5, 0.65];
export const DEVICE_COVERAGE = [0.5, 0.75, 0.95];
export const DEVICE_CRED = [1.15, 1, 0.8];
export function endpointMultiplier(edr = 1, deviceManagement = 1) {
  return (1 - idx(EDR_EFFECTIVENESS, edr) * idx(DEVICE_COVERAGE, deviceManagement)) / (1 - 0.2 * 0.75);
}
// Scenario elasticities (not measured): attacker AI on lures and credential attacks.
export const M_EXP_PHISH = 0.5;
export const M_EXP_CRED = 0.3;
// Visual / structural only: share of strikes that pass the first check at the default level.
export const CRED_CHECK_PASS = 0.5;
export const PHISH_CHECK_PASS = 0.3;

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
export type CompanySize = "small" | "mid" | "large";
// e calibrated to Cyentia IRIS 2020/2025: annual chance of a publicly known cyber event, all causes ~2% / 9.3% / 25%.
export const SIZE_EXPOSURE: Record<CompanySize, number> = { small: 0.0075, mid: 0.0361, large: 0.1061 };
export const IRIS_TARGET: Record<CompanySize, number> = { small: 0.02, mid: 0.093, large: 0.25 };
export const UK_ATTACK_TARGET: Record<CompanySize, string> = { small: "42–46% (micro and small)", mid: "65% (medium)", large: "69% (large)" };
export const HARDENING_PASS = [1, 0.5, 0.24, 0.12, 0.06]; // relative: "halves per level" is an assumption
export const SOC_CONTAIN = [0, 0.25, 0.40, 0.55]; // scenario assumption: before data loss
export const SOC_SHRINK = [0, 0.30, 0.50, 0.70]; // scenario assumption: losses kept below the reporting line
export const GOV_LARGE = [0.5, 0.35, 0.2, 0.1];
export const HARDENING_SIZE = [1, 0.85, 0.7, 0.55, 0.4];
export const VULN_SHARE_RANGE = [0.12, 0.31] as const; // s: share of all breaches that start with a vulnerability

export type ChannelResult = { lightning: number; raceP: number; // vendor: P(attacker wins); own: relative risk R_own vs today
  winsRace: number; reached: number; pastHardening: number; anyBreaches: number; breaches: number };
export type CompanyResult = {
  vendor: ChannelResult;
  own: ChannelResult;
  cred: ChannelResult;
  phish: ChannelResult;
  pretext: ChannelResult;
  other: { breaches: number; anyBreaches: number; incidents: number; events: number; exposedShare: number };
  supplier: { breaches: number; anyBreaches: number; incidents: number; largeShare: number; vendors: number; vendorIncidents: number; notices: number; takenShare: number; reportedShare: number };
  channels: Record<ChannelKey, number>; // reported breaches per year by channel
  lambdaVuln: number;
  vulnShareOfTotal: number;
  lambda: number; // reported breaches per year, all causes
  reportedShare: number;
  socContain: number;
  socShrink: number;
  reachProbability: number;
  hardeningProbability: number;
  saturated: boolean;
  rates: { reached: EventRate; incidents: EventRate; any: EventRate; reported: EventRate };
  allCauseIncidentChance: [number, number];
  allCauseReachedChance: [number, number];
  allCauseReportedChance: [number, number];
  pYear: number;
  p5: number;
  largeShare: number;
  lambdaLarge: number;
  pLarge5: number;
  allCause: [number, number];
  vulnerabilityShare: [number, number];
  lambdaBaseline: number;
};

export type EventRate = { lambda: number; pYear: number; p5: number };
export const eventRate = (lambda: number): EventRate => ({ lambda, pYear: 1 - Math.exp(-lambda), p5: 1 - Math.exp(-5 * lambda) });

const idx = (arr: readonly number[], i: number) => arr[Math.max(0, Math.min(arr.length - 1, Math.round(i)))] ?? 0;

// Attacker-AI exponents (assumptions): m acts on every attack step.
// Scenario elasticities (not measured).
export const M_EXP_COVERAGE = 0.5; // L_own = N_o·f·m^0.5
export const M_EXP_EXPLOIT = 0.5; // n-day delays / m^0.5
export const M_EXP_HARDENING = 0.3; // h = min(1, e·h_H·m^0.3)
export const M_EXP_SOC = 0.3; // c_eff = c_S / m^0.3

export type ModelParams = { zv: number; u?: number; eScale: number; expCoverage: number; expExploit: number; expHardening: number; expSoc: number };
export const CENTRAL_PARAMS: ModelParams = { zv: VENDOR_ZERO_DAY_SHARE, eScale: 1, expCoverage: M_EXP_COVERAGE, expExploit: M_EXP_EXPLOIT, expHardening: M_EXP_HARDENING, expSoc: M_EXP_SOC };
// Uncertainty variants keep the user's u (never-patched slider); they vary only z_v, e and the elasticities.
export const LOW_PARAMS: ModelParams = { zv: 0.19, eScale: 0.5, expCoverage: 0, expExploit: 0, expHardening: 0, expSoc: 0 };
export const HIGH_PARAMS: ModelParams = { zv: 0.31, eScale: 2, expCoverage: 1, expExploit: 1, expHardening: 0.5, expSoc: 0.5 };

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

function vulnRisk(c: CompanyInputs, P: ModelParams) {
  const ai = aiAmplifiers(c);
  const m = ai.vuln;
  const u = P.u ?? c.neverPatched;
  const reportedShare = 1 - Math.max(0.4, Math.min(0.9, c.smallBreachShare ?? 0.7));
  const e = calibratedExposure(c.size ?? "mid") * P.eScale;
  const rawReach = e / reportedShare;
  const rawHardening = idx(HARDENING_PASS, c.hardening) * Math.pow(ai.entry, P.expHardening);
  const reach = Math.min(1, rawReach);
  const hardening = Math.min(1, rawHardening);
  const pass = reach * hardening;
  // Reach caps when e × eScale exceeds the reporting share (e.g. large at r = 0.1,
  // or mid-size in the High range at r = 0.1). AI can also saturate hardening.
  const saturated = rawReach > 1 + 1e-12 || rawHardening > 1 + 1e-12;
  // Keep the old arithmetic exactly in the non-saturated calibrated regime.
  const reportedPass = saturated ? pass * reportedShare : Math.min(1, e * idx(HARDENING_PASS, c.hardening) * Math.pow(ai.entry, P.expHardening));
  const contain = idx(SOC_CONTAIN, c.soc) / Math.pow(ai.entry, P.expSoc);
  const shrink = idx(SOC_SHRINK, c.soc) / Math.pow(ai.entry, P.expSoc);
  const escape = 1 - contain;
  const pass0 = e * idx(HARDENING_PASS, c.hardening);
  const escape0 = 1 - idx(SOC_CONTAIN, c.soc);
  // Keep hot-reloaded sessions from older model versions valid when a new input is introduced.
  const vendorGrowth = c.vendorGrowth ?? DEFAULT_COMPANY.vendorGrowth;

  const vendor = channel(c.vendorVulns * (1 - c.inHouse) * vendorGrowth, vendorRace(c.patchDays, u, m, P.zv, P.expExploit), pass, escape, reach, reportedShare, reportedPass, shrink);

  const defend = idx(APPSEC_FIND_RATE, c.appsec) + BOUNTY_MAX_RATE * c.bountyK / (c.bountyK + BOUNTY_HALF_K);
  // Race 2 (article formula): attacker share of discovery races and the zero-day window shrink with defender speed D.
  const D = 1 + defend;
  const ownRiskMultiplier = (threat: number) => {
    const attackerWin = threat * OWN_BASE_ATTACKER_WIN / (threat * OWN_BASE_ATTACKER_WIN + D * (1 - OWN_BASE_ATTACKER_WIN));
    return attackerWin / OWN_BASE_ATTACKER_WIN / D;
  };
  const rOwn = ownRiskMultiplier(m);
  // L_own = N_o · f · focus · m^elasticity (elasticity is user-set only in advanced AI mode).
  const ownFocus = Math.max(1, c.ownFocus ?? 1);
  const ownElasticity = c.advancedAI && c.ownFocusElasticity != null ? c.ownFocusElasticity : P.expCoverage;
  const own = channel(OWN_BUGS_PER_YEAR * c.inHouse * ownFocus * Math.pow(m, ownElasticity), rOwn, pass, escape, reach, reportedShare, reportedPass, shrink);

  const lambda = vendor.breaches + own.breaches;
  const reached = vendor.reached + own.reached;
  const incidents = vendor.pastHardening + own.pastHardening;
  const any = vendor.anyBreaches + own.anyBreaches;
  const rates = { reached: eventRate(reached), incidents: eventRate(incidents), any: eventRate(any), reported: eventRate(lambda) };
  const allCauseIncidentChance = VULN_SHARE_RANGE.map((s) => 1 - Math.exp(-incidents / s)).sort((a, b) => a - b) as [number, number];
  const allCauseReachedChance = VULN_SHARE_RANGE.map((s) => 1 - Math.exp(-reached / s)).sort((a, b) => a - b) as [number, number];
  const allCauseReportedChance = VULN_SHARE_RANGE.map((s) => 1 - Math.exp(-lambda / s)).sort((a, b) => a - b) as [number, number];
  // All-cause calibration holds today's vulnerability environment fixed (k_v = 1, m = 1).
  const baselineVendor = channel(c.vendorVulns * (1 - c.inHouse), vendorRace(c.patchDays, u, 1, P.zv), pass0, escape0, reach, reportedShare, pass0, idx(SOC_SHRINK, c.soc));
  const baselineOwn = channel(OWN_BUGS_PER_YEAR * c.inHouse, ownRiskMultiplier(1), pass0, escape0, reach, reportedShare, pass0, idx(SOC_SHRINK, c.soc));
  const lambdaBaseline = baselineVendor.breaches + baselineOwn.breaches;
  const allCauseValues = VULN_SHARE_RANGE.map((s) => lambda + lambdaBaseline * (1 - s) / s);
  const allCause = [Math.min(...allCauseValues), Math.max(...allCauseValues)] as [number, number];
  const vulnerabilityShareValues = allCause.map((total) => lambda / total);
  const vulnerabilityShare = [Math.min(...vulnerabilityShareValues), Math.max(...vulnerabilityShareValues)] as [number, number];
  const largeShare = idx(GOV_LARGE, c.governance) * (1 - shrink) * idx(HARDENING_SIZE, c.hardening);
  const lambdaLarge = lambda * largeShare;
  return {
    vendor, own, lambda, reportedShare, reportedPass, escape, socContain: contain, socShrink: shrink, m, reachProbability: reach, hardeningProbability: hardening, saturated, rates, allCauseIncidentChance, allCauseReachedChance, allCauseReportedChance,
    pYear: 1 - Math.exp(-lambda),
    p5: 1 - Math.exp(-5 * lambda),
    largeShare, lambdaLarge,
    pLarge5: 1 - Math.exp(-5 * lambdaLarge),
    allCause, vulnerabilityShare, lambdaBaseline,
  };
}

export function computeRisk(c: CompanyInputs, P: ModelParams = CENTRAL_PARAMS): CompanyResult {
  const v = vulnRisk(c, P);
  const ai = aiAmplifiers(c);
  // Calibration point: the vulnerability rate at default settings for this size and reporting share.
  const d = { ...DEFAULT_COMPANY, size: c.size ?? "mid", smallBreachShare: c.smallBreachShare ?? 0.7 };
  const v0 = vulnRisk(d, P);
  const k0 = v0.reportedPass * v0.escape * (1 - v0.socShrink); // default hardening × both SOC gates
  const base = (share: number, checkPass: number) => v0.lambda * share / CHANNEL_SHARE.vuln / (checkPass * k0);
  const id = c.identity ?? 1, devices = c.deviceManagement ?? 1;
  const credPass = Math.min(1, CRED_CHECK_PASS * idx(IDENTITY_CRED, id) * idx(DEVICE_CRED, devices));
  const phishPass = Math.min(1, PHISH_CHECK_PASS * idx(IDENTITY_PHISH, id) * idx(EMAIL_FILTERING, c.emailFiltering ?? 1) * idx(TRAINING_PHISH, c.training ?? 1) * endpointMultiplier(c.edr ?? 1, devices));
  const reach = v.reachProbability;
  const pass = reach * v.hardeningProbability;
  const cred = channel(base(CHANNEL_SHARE.cred, CRED_CHECK_PASS) * Math.pow(ai.cred, M_EXP_CRED) * (c.credentialExposure ?? 1), credPass, pass, v.escape, reach, v.reportedShare, v.reportedPass, v.socShrink);
  const phish = channel(base(CHANNEL_SHARE.phish, PHISH_CHECK_PASS) * Math.pow(ai.phish, M_EXP_PHISH) * (c.phishingPressure ?? 1), phishPass, pass, v.escape, reach, v.reportedShare, v.reportedPass, v.socShrink);
  // Calls, chat and help-desk tricks: modest Identity effect only, then common gates.
  // No email/training/EDR, device or phishing-AI multiplier is applied to this channel.
  const pretextCheck = 0.3; // illustrative first-check pass rate, normalized at default
  const pretext = channel(base(CHANNEL_SHARE.pretext, pretextCheck), Math.min(1, pretextCheck * idx(IDENTITY_PRETEXT, id)), pass, v.escape, reach, v.reportedShare, v.reportedPass, v.socShrink);
  const supShare = Math.min(SUPPLIER_SHARE_RANGE[1], Math.max(SUPPLIER_SHARE_RANGE[0], c.supplierShare ?? CHANNEL_SHARE.supplier));
  const otherL = v0.lambda * (RESIDUAL_POOL - supShare) / CHANNEL_SHARE.vuln; // fixed: no slider moves it
  const otherAny = otherL / (v.reportedShare * (1 - v.socShrink));
  const otherIncidents = otherAny / Math.max(1e-9, v.escape);
  const otherEvents = RESIDUAL_EVENTS_MID * calibratedExposure(c.size ?? "mid") / calibratedExposure("mid");
  // Events → data exposed (calibrated so the publicly known rate stays fixed) → SOC/escape → publicly known.
  const other = { breaches: otherL, anyBreaches: otherAny, incidents: otherIncidents, events: Math.max(otherEvents, otherIncidents), exposedShare: Math.min(1, otherIncidents / Math.max(otherEvents, otherIncidents, 1e-12)) };
  // Data lost outside your network: only supplier security changes frequency.
  // Governance changes the large-breach share, not your hardening/SOC/EDR gates.
  // Attackers hit vendors too: vulnpocalypse on the vulnerability-driven part, attacker AI with a modest elasticity.
  const kv = c.vendorGrowth ?? 1;
  const supplierThreat = ((1 - CHANNEL_SHARE.vuln) + CHANNEL_SHARE.vuln * kv) * Math.pow(Math.max(1, c.threat ?? 1), M_EXP_SUPPLIER);
  // Funnel: vendors × IRIS rate → notices involving your data → data actually taken → publicly known.
  // Supplier reporting is independent of the shared reporting slider: most losses are
  // small or reported under the vendor's name. Calibrate at the default vendor count.
  const vendors0 = VENDORS_BY_SIZE[c.size ?? "mid"];
  const vendors = Math.min(VENDORS_RANGE[1], Math.max(VENDORS_RANGE[0], c.vendorsHolding ?? vendors0));
  const vendorIncidents = vendors * VENDOR_INCIDENT_RATE * supplierThreat;
  const notices = vendorIncidents * VENDOR_IN_SCOPE;
  const supplierReportedShare = Math.min(1, (v0.lambda * supShare / CHANNEL_SHARE.vuln) / (vendors0 * VENDOR_INCIDENT_RATE * VENDOR_IN_SCOPE * SUPPLIER_TAKEN_SHARE));
  const takenShare = Math.min(1, SUPPLIER_TAKEN_SHARE * idx(SUPPLIER_SECURITY, c.supplierSecurity ?? 1));
  const supplierTaken = notices * takenShare;
  const supplierL = supplierTaken * supplierReportedShare;
  const supplierLarge = Math.min(1, SUPPLIER_LARGE_MULTIPLIER * v0.largeShare * idx(GOV_LARGE, c.governance) / idx(GOV_LARGE, d.governance));
  const supplier = { breaches: supplierL, anyBreaches: supplierTaken, incidents: supplierTaken, largeShare: supplierLarge, vendors, vendorIncidents, notices, takenShare, reportedShare: supplierReportedShare };
  const channels = { vuln: v.lambda, cred: cred.breaches, phish: phish.breaches, pretext: pretext.breaches, other: otherL, supplier: supplierL };
  const lambda = Object.values(channels).reduce((a, b) => a + b, 0);
  const sum = (k: "reached" | "pastHardening" | "anyBreaches") => v.vendor[k] + v.own[k] + cred[k] + phish[k] + pretext[k];
  const rates = { reached: eventRate(sum("reached")), incidents: eventRate(sum("pastHardening") + other.incidents + supplier.incidents), any: eventRate(sum("anyBreaches") + other.anyBreaches + supplier.anyBreaches), reported: eventRate(lambda) };
  const lambdaLarge = (lambda - supplierL) * v.largeShare + supplierL * supplier.largeShare;
  return {
    ...v, cred, phish, pretext, other, supplier, channels, lambdaVuln: v.lambda, vulnShareOfTotal: v.lambda / lambda, lambda, rates, largeShare: lambda > 0 ? lambdaLarge / lambda : 0,
    allCauseReportedChance: [1 - Math.exp(-lambda), 1 - Math.exp(-lambda)],
    pYear: 1 - Math.exp(-lambda), p5: 1 - Math.exp(-5 * lambda), lambdaLarge, pLarge5: 1 - Math.exp(-5 * lambdaLarge),
  };
}

function channel(lightning: number, raceP: number, pass: number, escape: number, reach: number, reportedShare: number, reportedPass = pass, shrink = 0): ChannelResult {
  const winsRace = lightning * raceP;
  const pastHardening = winsRace * pass;
  const breaches = (winsRace * reportedPass) * escape * (1 - shrink);
  return { lightning, raceP, winsRace, reached: winsRace * reach, pastHardening, anyBreaches: pastHardening * escape, breaches };
}

export const DEFAULT_COMPANY: CompanyInputs = { vendorVulns: 6, patchDays: 43, neverPatched: 0.1, appsec: 1, bountyK: 0, hardening: 1, soc: 1, governance: 1, inHouse: 0.4, threat: 1, vendorGrowth: 1, smallBreachShare: 0.7, size: "mid", identity: 1, emailFiltering: 1, training: 1, edr: 1, deviceManagement: 1, credentialExposure: 1, phishingPressure: 1, supplierShare: 0.25, supplierSecurity: 1 };

/** Solve e at full precision; SIZE_EXPOSURE lists the review's rounded values only.
 * Using rounded e directly would miss the exact annual IRIS probability targets.
 */
export function calibratedExposure(size: CompanySize): number {
  const d = DEFAULT_COMPANY;
  const defend = idx(APPSEC_FIND_RATE, d.appsec) + BOUNTY_MAX_RATE * d.bountyK / (d.bountyK + BOUNTY_HALF_K);
  const D = 1 + defend;
  const ownWin = OWN_BASE_ATTACKER_WIN / (OWN_BASE_ATTACKER_WIN + D * (1 - OWN_BASE_ATTACKER_WIN)) / OWN_BASE_ATTACKER_WIN / D;
  const wins = d.vendorVulns * (1 - d.inHouse) * vendorRace(d.patchDays, d.neverPatched) + OWN_BUGS_PER_YEAR * d.inHouse * ownWin;
  const defaultGates = idx(HARDENING_PASS, d.hardening) * (1 - idx(SOC_CONTAIN, d.soc)) * (1 - idx(SOC_SHRINK, d.soc));
  return -Math.log1p(-IRIS_TARGET[size]) * CHANNEL_SHARE.vuln / (wins * defaultGates);
}
