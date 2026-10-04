const VENDOR_ZERO_DAY_SHARE = 0.31;
const NDAY_BINS = [[3, 0.293], [12, 0.087], [21, 0.084], [39.5, 0.123], [84, 0.059], [131, 0.131], [259, 0.123], [626, 0.101]];
const CHANNEL_SHARE = { vuln: 0.2, cred: 0.22, phish: 0.16, other: 0.42 };
const IDENTITY_CRED = [1.6, 1, 0.4, 0.15];
const IDENTITY_PHISH = [1.3, 1, 0.7, 0.35];
const EMAIL_PHISH_OLD = [1.3, 1, 0.6];
const EMAIL_PHISH_NEW = [1.3, 1, 0.8];
const TRAINING = [1.15, 1, 0.8];
const EDR_EFF = [0, 0.2, 0.5, 0.65];
const EDR_COV = [0.5, 0.75, 0.95];
const CRED_DEVICE = [1.15, 1, 0.8];

const CRED_CHECK_PASS = 0.5;
const PHISH_CHECK_PASS = 0.3;
const SIZE_EXPOSURE = { small: 0.0046, mid: 0.0224, large: 0.066 };
const HARDENING_PASS = [1, 0.5, 0.24, 0.12, 0.06];
const SOC_CONTAIN = [0, 0.4, 0.65, 0.85];

const M_EXP_PHISH = 0.5;
const M_EXP_CRED = 0.3;
const M_EXP_COVERAGE = 0.5;
const M_EXP_EXPLOIT = 0.5;
const M_EXP_HARDENING = 0.3;
const M_EXP_SOC = 0.3;

const idx = (arr, i) => arr[Math.max(0, Math.min(arr.length - 1, Math.round(i)))] ?? 1;

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
  return { breaches };
}

function compute(c) {
  const m = 1;
  const reportedShare = 0.3;
  const e = SIZE_EXPOSURE.mid;
  const reach = e / reportedShare;
  const hardening = idx(HARDENING_PASS, c.hardening);
  const pass = reach * hardening;
  const reportedPass = e * hardening;
  const escape = 1 - idx(SOC_CONTAIN, c.soc);

  // Calibration
  const pass0 = e * 0.5; // default hardening 1
  const escape0 = 1 - 0.4; // default soc 1
  const k0 = pass0 * escape0;
  
  const v0_race = vendorRace(43, 0.1, 1, 0.31, 0.5);
  // D = 1 + APPSEC_FIND_RATE[1] = 1.5
  const v0_own_win = 0.35 / (0.35 + 1.5 * 0.65);
  const v0_own_mult = v0_own_win / 0.35 / 1.5;
  const v0_lambda = (6 * 0.6 * v0_race + 1.5 * 0.4 * v0_own_mult) * k0;

  const vendor = channel(6 * 0.6, v0_race, pass, escape, reach, reportedShare, reportedPass);
  const own = channel(1.5 * 0.4, v0_own_mult, pass, escape, reach, reportedShare, reportedPass);
  
  const base = (share, checkPass) => v0_lambda * share / 0.2 / (checkPass * k0);

  const credPass = Math.min(1, CRED_CHECK_PASS * idx(IDENTITY_CRED, c.identity) * idx(CRED_DEVICE, c.credDeviceIdx));
  const phishPass = Math.min(1, PHISH_CHECK_PASS * idx(IDENTITY_PHISH, c.identity) * idx(EMAIL_PHISH_NEW, c.emailIdx) * idx(TRAINING, c.trainingIdx) * c.edrFactor);

  const cred = channel(base(0.22, 0.5), credPass, pass, escape, reach, reportedShare, reportedPass);
  const phish = channel(base(0.16, 0.3), phishPass, pass, escape, reach, reportedShare, reportedPass);
  const otherL = v0_lambda * 0.42 / 0.2;

  return vendor.breaches + own.breaches + cred.breaches + phish.breaches + otherL;
}

const def = { hardening: 1, soc: 1, identity: 1, emailIdx: 1, trainingIdx: 1, credDeviceIdx: 1, edrFactor: 1 };
console.log("Default: " + compute(def).toFixed(4));

const regTraining = { ...def, trainingIdx: 1 };
console.log("Regular training: " + compute(regTraining).toFixed(4));

const edrFactor = (1 - 0.5 * 0.95) / 0.85;
const edrManaged = { ...def, soc: 2, edrFactor: edrFactor, emailIdx: 2 };
console.log("EDR index 2 + managed index 2: " + compute(edrManaged).toFixed(4));

// For MFA index 3, we use identity 3 and the best of other factors provided
const mfa3 = { ...def, identity: 3, credDeviceIdx: 2, trainingIdx: 2, emailIdx: 2 };
console.log("Phishing-resistant MFA index 3: " + compute(mfa3).toFixed(4));

// Also check if they meant "only" those changes
const mfa3_only = { ...def, identity: 3, credDeviceIdx: 2 };
console.log("Phishing-resistant MFA index 3 (only identity/device): " + compute(mfa3_only).toFixed(4));
