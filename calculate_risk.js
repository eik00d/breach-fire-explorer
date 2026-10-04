const VENDOR_ZERO_DAY_SHARE = 0.31;
const NDAY_BINS = [[3, 0.293], [12, 0.087], [21, 0.084], [39.5, 0.123], [84, 0.059], [131, 0.131], [259, 0.123], [626, 0.101]];
const CHANNEL_SHARE = { vuln: 0.2, cred: 0.22, phish: 0.16, other: 0.42 };
const IDENTITY_CRED = [1.6, 1, 0.4, 0.15];
const IDENTITY_PHISH = [1.3, 1, 0.7, 0.35];
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

const idx = (arr, i) => arr[Math.max(0, Math.min(arr.length - 1, Math.round(i)))] ?? 1;

function lateShare(patchDays, m = 1) {
  return NDAY_BINS.reduce((sum, [days, share]) => sum + share * Math.pow(0.5, days / patchDays), 0);
}

function vendorRace(patchDays, neverPatched) {
  const F = lateShare(patchDays, 1);
  return 0.31 + 0.69 * (neverPatched + (1 - neverPatched) * F);
}

function channel(lightning, raceP, pass, escape, reportedPass) {
  const winsRace = lightning * raceP;
  return (winsRace * reportedPass) * escape;
}

function compute(c) {
  const e = SIZE_EXPOSURE.mid;
  const hardening = idx(HARDENING_PASS, c.hardening);
  const escape = 1 - idx(SOC_CONTAIN, c.soc);
  const reportedPass = e * hardening;

  // Calibration k0
  const k0 = (e * 0.5) * (1 - 0.4);
  
  const v0_race = vendorRace(43, 0.1);
  const v0_own_win = 0.35 / (0.35 + 1.5 * 0.65);
  const v0_own_mult = v0_own_win / 0.35 / 1.5;
  const v0_lambda = (6 * 0.6 * v0_race + 1.5 * 0.4 * v0_own_mult) * k0;

  const vendor = channel(6 * 0.6, v0_race, 0, escape, reportedPass);
  const own = channel(1.5 * 0.4, v0_own_mult, 0, escape, reportedPass);
  
  const base = (share, checkPass) => v0_lambda * share / 0.2 / (checkPass * k0);

  const credPass = Math.min(1, CRED_CHECK_PASS * idx(IDENTITY_CRED, c.identity) * idx(CRED_DEVICE, c.credDeviceIdx));
  
  const edrFactor = (1 - idx(EDR_EFF, c.edrIdx) * idx(EDR_COV, c.covIdx)) / 0.85;
  const phishPass = Math.min(1, PHISH_CHECK_PASS * idx(IDENTITY_PHISH, c.identity) * idx(EMAIL_PHISH_NEW, c.emailIdx) * idx(TRAINING, c.trainingIdx) * edrFactor);

  const cred = channel(base(0.22, 0.5), credPass, 0, escape, reportedPass);
  const phish = channel(base(0.16, 0.3), phishPass, 0, escape, reportedPass);
  const otherL = v0_lambda * 0.42 / 0.2;

  return vendor + own + cred + phish + otherL;
}

console.log("1. Default (all index 1): " + compute({ hardening: 1, soc: 1, identity: 1, emailIdx: 1, trainingIdx: 1, credDeviceIdx: 1, edrIdx: 1, covIdx: 1 }).toFixed(4));
console.log("2. Regular training (same): " + compute({ hardening: 1, soc: 1, identity: 1, emailIdx: 1, trainingIdx: 1, credDeviceIdx: 1, edrIdx: 1, covIdx: 1 }).toFixed(4));
console.log("3. EDR index 2 + managed index 2: " + compute({ hardening: 1, soc: 2, identity: 1, emailIdx: 2, trainingIdx: 1, credDeviceIdx: 1, edrIdx: 2, covIdx: 2 }).toFixed(4));
console.log("4. Phishing-resistant MFA index 3 (cumulative): " + compute({ hardening: 1, soc: 2, identity: 3, emailIdx: 2, trainingIdx: 2, credDeviceIdx: 2, edrIdx: 2, covIdx: 2 }).toFixed(4));
