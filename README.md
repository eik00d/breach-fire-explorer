# The Forest Fire of Cyber Breaches

A single-page interactive explainer in the style of a Veritasium video: **why one breach can outweigh a thousand**. Tone: curious, playful, honest — each section starts with a question, lets the reader guess or play, then reveals the answer. Clean, light design, large type, lots of white space, smooth animations, mobile-friendly.

**Live app**: https://breach-fire-explorer.lovable.app

No backend: every calculation runs in the reader's browser, all data is embedded in the code. React 19 + TanStack Start + Tailwind v4 + Recharts + canvas.

## What's on the page

**Section 01 — My Company (the calculator).** Eight-plus sliders: patching speed, attacker AI, AppSec & bug bounty, hardening & network segmentation, SOC, data governance, share of small breaches, and a company-size selector (Small / Mid-size / Very large, calibrated to Cyentia IRIS 2020/2025 annual cyber-event rates of ~2% / 9.3% / 25%).

- An animated canvas replays the model: a seeded, deterministic grid where lightning (attacks) hits vendor and own-code systems, exploits race against patching, fires spread through visible network segments, SOC crews respond, and small vs reported vs large breaches are drawn distinctly. Mollii — strikes that never reached you, blocked-by-hardening bounces, and SOC saves are all shown.
- Two race bars (your code vs vendor patch; lightning hitting you), a funnel (strikes → reached you → past hardening → breaches), and a results grid with four incident rates, one-year / five-year / large-breach chances.
- A "Reality check" box compares model outputs with published data: Cyentia IRIS (reported breaches) and the UK Cyber Security Breaches Survey 2025/26 (attacks that reached you).
- The canvas is an illustrative replay driven by `computeRisk` — the closed-form model in `src/lib/company-risk.ts` is the only source of numbers, never the sim.

**Section 02 — The real data.** Log-log CCDF chart with exact points only (no interpolation/extrapolation): US healthcare hacking breaches 2016–15 Sep 2026 (HHS registry, start 100,000 people), all-sector EuRepoC documented losses (start $10M, line ends at ×100), dashed 1/x reference, and dotted insurance-claims slope −0.74 (Henderson et al., 2026). Eight named giants placed exactly on the HHS series (Anthem and Premera 2015 are outside the 2016–2026 window and omitted).

**Section 03 — The 1% that decides everything.** Concentration slider: the top 1% of breaches account for 57% of all people affected; Change Healthcare alone is 22% of everyone affected since 2016.

**Section 04 — A thousand futures.** Monte Carlo, 1,000 futures for 2027–2031. Yearly counts of 1M+ breaches ~ Poisson(λ₁ × k), where λ₁ is the baseline slider ("US healthcare, 2021–2026 average; yearly counts ranged from 10 to 37…") and k = (1 − s) + s·g with s the vulnerability share and g the exploitation-growth multiplier (presets 1 / 2.2 / 5.7 → 49% / 60% / 81% of futures seeing a 100M+ breach by the start of 2031).

**Footer** distinguishes measured / modelled / inferred claims and lists sources (HHS, EuRepoC, Cyentia IRIS 2025, UK Cyber Security Breaches Survey 2025/26, Verizon DBIR 2026, Henderson et al. 2026) plus a link to the full article: https://asintsov.com/notes/2026-10-05-vulnpocalypse-is-a-race/

## Key files

- `src/components/breach-story.tsx` — the whole page: sections, calculator UI, canvas, charts.
- `src/lib/company-risk.ts` — closed-form risk model (the only source of numbers for the tables).
- `src/lib/company-sim.ts` — deterministic seeded cell simulation that visualises the same funnel.
- `src/lib/vuln-data.ts` — CVE/KEV per-year statistics embedded in the bundle.

## Model conventions

- Simulations are deterministic when seeded (Mulberry32), so visual comparisons are reproducible.
- Uploaded datasets never enter the client bundle — only reviewed aggregates are embedded.
- Measured, modelled and inferred values are labelled separately in the footer.
- Exploitation growth is `g` in the futures section; `m` is reserved for "Attacker AI" in the calculator.

## Development

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```

## Deploy to GitHub Pages

The site builds to a fully static bundle (no server code). `.github/workflows/deploy-pages.yml` deploys it on every push to `main` (or manually via **Run workflow**), building with `GH_PAGES=1` and a `/<repo-name>/` base path. One-time setup in the GitHub repo: **Settings → Pages → Source: GitHub Actions**. The site appears at `https://<login>.github.io/<repo-name>/`.

Note: GitHub may reject workflow files pushed by the Lovable app — if Actions is empty, create `.github/workflows/deploy-pages.yml` manually on GitHub with the same content.
