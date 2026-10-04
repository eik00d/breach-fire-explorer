const VENDOR_ZERO_DAY_SHARE = 0.31;
const NDAY_BINS = [[3, 0.293], [12, 0.087], [21, 0.084], [39.5, 0.123], [84, 0.059], [131, 0.131], [259, 0.123], [626, 0.101]];
const CHANNEL_SHARE = { vuln: 0.2, cred: 0.22, phish: 0.16, other: 0.42 };
const IDENTITY_CRED = [1.6, 1, 0.4, 0.15];
const IDENTITY_PHISH = [1.3, 1, 0.7, 0.35];
const EMAIL_PHISH_CURRENT = [1.3, 1, 0.6];
const CRED_CHECK_PASS = 0.5;
const PHISH_CHECK_PASS = 0.3;
const SIZE_EXPOSURE = { small: 0.0046, mid: 0.0224, large: 0.066 };
const HARDENING_PASS = [1, 0.5, 0.24, 0.12, 0.06];
const SOC_CONTAIN = [0, 0.4, 0.65, 0.85];
const GOV_LARGE = [0.5, 0.35, 0.2, 0.1];
const HARDENING_SIZE = [1, 0.85, 0.7, 0.55, 0.4];
const OWN_BASE_ATTACKER_WIN = 0.35;
const OWN_BUGS_PER_YEAR = 1.5;
const APPSEC_FIND_RATE = [0, 0.5, 1.5, 3];
const BOUNTY_MAX_RATE = 2;
const BOUNTY_HALF_K = 250;

const M_EXP_PHISH = 0.5;
const M_EXP_CRED = 0.3;
const M_EXP_COVERAGE = 0.5;
const M_EXP_EXPLOIT = 0.5;
const M_EXP_HARDENING = 0.3;
const M_EXP_SOC = 0.3;

const idx = (arr, i) => arr[Math.max(0, Math.min(arr.length - 1, Math.round(i)))] ?? 0;

function lateShare(patchDays, m = 1, expExploit = M_EXP_EXPLOIT) {
  const speed = Math.pow(m, expExploit);
  return NDAY_BINS.reduce((sum, [days, share]) => sum + share * Math.pow(0.5, days / speed / patchDays), 0);
}

function vendorRace(patchDays, neverPatched, m = 1, zv = VENDOR_ZERO_DAY_SHARE, expExploit = M_EXP_EXPLOIT) {
  const F = lateShare(patchDays, m, expExploit);
  return zv + (1 - zv) * (neverPatched + (1 - neverPatched) * F);
}

function channel(lightning, raceP, pass, escape, reach, reportedShare, reportedPass) {
  const winsRace = lightning * raceP;
  const pastHardening = winsRace * pass;
  const breaches = (winsRace * reportedPass) * escape;
  return { lightning, raceP, winsRace, reached: winsRace * reach, pastHardening, anyBreaches: breaches / reportedShare, breaches };
}

function computeRisk(c, P) {
  const m = Math.max(1, c.threat ?? 1);
  const u = P.u ?? c.neverPatched;
  const reportedShare = 1 - Math.max(0.4, Math.min(0.9, c.smallBreachShare ?? 0.7));
  const e = SIZE_EXPOSURE[c.size ?? "mid"] * P.eScale;
  const rawReach = e / reportedShare;
  const rawHardening = idx(HARDENING_PASS, c.hardening) * Math.pow(m, P.expHardening);
  const reach = Math.min(1, rawReach);
  const hardening = Math.min(1, rawHardening);
  const pass = reach * hardening;
  const reportedPass = Math.min(1, e * idx(HARDENING_PASS, c.hardening) * Math.pow(m, P.expHardening));
  const contain = idx(SOC_CONTAIN, c.soc) / Math.pow(m, P.expSoc);
  const escape = 1 - contain;

  const vendor = channel(c.vendorVulns * (1 - c.inHouse) * c.vendorGrowth, vendorRace(c.patchDays, u, m, P.zv, P.expExploit), pass, escape, reach, reportedShare, reportedPass);

  const defend = idx(APPSEC_FIND_RATE, c.appsec) + BOUNTY_MAX_RATE * c.bountyK / (c.bountyK + BOUNTY_HALF_K);
  const D = 1 + defend;
  const ownRiskMultiplier = (threat) => {
    const attackerWin = threat * OWN_BASE_ATTACKER_WIN / (threat * OWN_BASE_ATTACKER_WIN + D * (1 - OWN_BASE_ATTACKER_WIN));
    return attackerWin / OWN_BASE_ATTACKER_WIN / D;
  };
  const rOwn = ownRiskMultiplier(m);
  const own = channel(OWN_BUGS_PER_YEAR * c.inHouse * Math.pow(m, P.expCoverage), rOwn, pass, escape, reach, reportedShare, reportedPass);

  const lambdaVuln = vendor.breaches + own.breaches;

  // Baseline for calibration
  const d = { 
    vendorVulns: 6, patchDays: 43, neverPatched: 0.1, appsec: 1, bountyK: 0, hardening: 1, soc: 1, governance: 1, inHouse: 0.4, threat: 1, vendorGrowth: 1, smallBreachShare: 0.7, size: c.size ?? "mid", identity: 1, email: 1, credentialExposure: 1, phishingPressure: 1 
  };
  // We need v0 for calibration
  const e0 = SIZE_EXPOSURE[d.size] * P.eScale;
  const pass0 = e0 * idx(HARDENING_PASS, d.hardening);
  const escape0 = 1 - idx(SOC_CONTAIN, d.soc);
  const k0 = pass0 * escape0;
  
  // v0.lambda calculation (vulnerability only)
  const v0_m = 1;
  const v0_u = 0.1;
  const v0_reportedShare = 0.3;
  const v0_vendorRace = vendorRace(43, 0.1, 1, P.zv, P.expExploit);
  const v0_ownRiskMult = ownRiskMultiplier(1);
  const v0_vendorBreaches = (6 * 0.6 * v0_vendorRace) * pass0 * escape0;
  const v0_ownBreaches = (1.5 * 0.4 * v0_ownRiskMult) * pass0 * escape0;
  const v0_lambda = v0_vendorBreaches + v0_ownBreaches;

  const base = (share, checkPass) => v0_lambda * share / CHANNEL_SHARE.vuln / (checkPass * k0);
  
  const id = c.identity ?? 1;
  const em = c.email ?? 1;
  
  // Apply new requested factors
  const emailFilter = c.emailFilterFactor ?? idx(EMAIL_PHISH_CURRENT, em);
  const trainingFactor = c.trainingFactor ?? 1;
  const edrFactor = c.edrFactor ?? 1;
  const credDeviceFactor = c.credDeviceFactor ?? 1;

  const credPass = Math.min(1, CRED_CHECK_PASS * idx(IDENTITY_CRED, id) * credDeviceFactor);
  const phishPass = Math.min(1, PHISH_CHECK_PASS * idx(IDENTITY_PHISH, id) * emailFilter * trainingFactor * edrFactor);

  const cred = channel(base(CHANNEL_SHARE.cred, CRED_CHECK_PASS) * Math.pow(m, M_EXP_CRED) * (c.credentialExposure ?? 1), credPass, pass, escape, reach, reportedShare, reportedPass);
  const phish = channel(base(CHANNEL_SHARE.phish, PHISH_CHECK_PASS) * Math.pow(m, M_EXP_PHISH) * (c.phishingPressure ?? 1), phishPass, pass, escape, reach, reportedShare, reportedPass);
  
  const otherL = v0_lambda * CHANNEL_SHARE.other / CHANNEL_SHARE.vuln;
  
  const lambda = lambdaVuln + cred.breaches + phish.breaches + otherL;
  
  return { lambda, lambdaVuln, cred: cred.breaches, phish: phish.breaches, other: otherL };
}

const DEFAULT_COMPANY = { vendorVulns: 6, patchDays: 43, neverPatched: 0.1, appsec: 1, bountyK: 0, hardening: 1, soc: 1, governance: 1, inHouse: 0.4, threat: 1, vendorGrowth: 1, smallBreachShare: 0.7, size: "mid", identity: 1, email: 1, credentialExposure: 1, phishingPressure: 1 };
const CENTRAL_PARAMS = { zv: 0.31, eScale: 1, expExploit: 0.5, expHardening: 0.3, expSoc: 0.3, expCoverage: 0.5 };

console.log("--- Default ---");
const resDefault = computeRisk(DEFAULT_COMPANY, CENTRAL_PARAMS);
console.log(resDefault);

console.log("\n--- Regular Training ---");
// New email filter values: [1.3, 1, 0.8]
// New training values: [1.15, 1, 0.8]
// Regular training = index 1 = 1.0
const companyTraining = { ...DEFAULT_COMPANY, emailFilterFactor: 1.0, trainingFactor: 1.0 };
const resTraining = computeRisk(companyTraining, CENTRAL_PARAMS);
console.log(resTraining);

console.log("\n--- EDR index 2 + Managed index 2 ---");
// EDR index 2: eff=0.5, cov=0.95 -> (1 - 0.5 * 0.95) / 0.85 = 0.6176
const edrFactor = (1 - 0.5 * 0.95) / 0.85;
// Managed index 2: soc=2
const companyEdrManaged = { ...DEFAULT_COMPANY, soc: 2, edrFactor: edrFactor, emailFilterFactor: 0.8 }; // index 2 of email filter [1.3, 1, 0.8]
const resEdrManaged = computeRisk(companyEdrManaged, CENTRAL_PARAMS);
console.log(resEdrManaged);

console.log("\n--- Phishing-resistant MFA index 3 ---");
// Identity index 3
// Credential device factor: [1.15, 1, 0.8] index 3? User might mean the 3rd index (0, 1, 2, 3) if they assume it matches Identity.
// Let's assume it's [1.15, 1, 0.8, 0.8] or something. But the user said "index 3".
// If they mean the 4th value, but only 3 provided, maybe the last value repeats or they made a mistake.
// Let's try index 3 (4th element) if we pad it, or use index 2 if they mean the 3rd element.
// Wait, "index 3" for MFA usually means level 3 (phishing resistant).
// Let's assume credDeviceFactor[3] = 0.8.
const companyMfa3 = { ...DEFAULT_COMPANY, identity: 3, credDeviceFactor: 0.8, emailFilterFactor: 0.8, trainingFactor: 0.8 };
const resMfa3 = computeRisk(companyMfa3, CENTRAL_PARAMS);
console.log(resMfa3);
