// Reviewed aggregates from the NVD CVE list and CISA KEV catalogue (2016 – 30 Sep 2026).
// Raw files stay out of the bundle; only these yearly counts are embedded.
export const CVE_PER_YEAR: Record<number, number> = {
  2016: 5539, 2017: 13365, 2018: 15926, 2019: 16282, 2020: 17498,
  2021: 20092, 2022: 24992, 2023: 28531, 2024: 39937, 2025: 47948,
  2026: Math.round(72225 * 365 / 273), // 72,225 published by 30 Sep, annualised
};
export const KEV_PER_YEAR: Record<number, number> = {
  2016: 51, 2017: 86, 2018: 76, 2019: 128, 2020: 146, 2021: 214,
  2022: 131, 2023: 165, 2024: 160, 2025: 197, 2026: Math.round(173 * 365 / 273),
};
/** Median days from publication to first known exploitation, KEV entries added 2023–2026. */
export const MEDIAN_DAYS_TO_EXPLOIT = 14;
/** Share of those exploited within 7 days. */
export const SHARE_EXPLOITED_WITHIN_WEEK = 0.44;

// Growth 2021 → 2026 (annualised): about 37% per year. Used for 2027–2031 projections.
export const CVE_GROWTH = Math.pow((CVE_PER_YEAR[2026] ?? 1) / (CVE_PER_YEAR[2021] ?? 1), 1 / 5);
export const LAST_MEASURED_YEAR = 2026;
export const YEARS = Array.from({ length: 16 }, (_, i) => 2016 + i);

export function cvesInYear(year: number) {
  const measured = CVE_PER_YEAR[year];
  if (measured) return measured;
  return Math.round((CVE_PER_YEAR[LAST_MEASURED_YEAR] ?? 0) * Math.pow(CVE_GROWTH, year - LAST_MEASURED_YEAR));
}

/** Forest parameters implied by a year: lightning ∝ CVEs published, patch decay ∝ CVEs published. */
export function yearToForest(year: number) {
  const cves = cvesInYear(year);
  return {
    lightning: Math.max(0.1, Math.round(cves / (CVE_PER_YEAR[2025] ?? 1) * 10) / 10), // × 2025 level
    decay: 0.002 * cves / (CVE_PER_YEAR[2025] ?? 1), // per day; 0.2%/day in 2025
  };
}
