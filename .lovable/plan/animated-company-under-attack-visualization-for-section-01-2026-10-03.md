# Animated "company under attack" visualization for Section 01

## Goal

Add a living canvas animation to the "Will lightning strike your company?" section that shows the same pipeline the calculator computes: lightning hits the perimeter → a system becomes vulnerable → the patch-vs-exploit race → fire breaks in → lateral movement spreads it through the company → hardening and the SOC fight it. Every slider the user moves visibly changes the animation.

## What the viewer sees

A canvas panel at the top of Section 01, above the Attack/Defense slider blocks:

```text
┌──────────────────────────────────────────┐
│  ☁ lightning                [company grid]│
│   ⚡ strikes a system → cell turns amber  │
│   (vulnerable, patch clock ticking)       │
│   → patched: turns blue again             │
│   → exploit wins: cell ignites orange     │
│   → fire spreads to neighboring cells     │
│   (lateral movement), hardening cells     │
│   resist, SOC crews extinguish fires      │
└──────────────────────────────────────────┘
```

- The grid is the company: a field of small squares ("systems"). The share of in-house vs vendor systems follows the "Built in-house vs vendors" slider (two tints).
- Lightning bolts fall at a rate proportional to L_v + L_o (vendor vulns, vendor growth, attacker AI sliders) — more lightning, more strikes.
- Each struck system gets a visible patch countdown ring. Patch-speed slider shortens it; "never patched" share means some rings never complete.
- If the exploit wins the race, the cell ignites. Fire then spreads cell-to-cell (lateral movement): hardening level makes cells fire-resistant (firebreaks), SOC level spawns "crew" markers that move to fires and put them out, governance caps how large a fire can grow.
- A small live counter under the canvas: "fires this year: N · systems burned: M" — illustrative, not the model's λ.

## Technical approach

- New module `src/lib/company-sim.ts`: a deterministic, seeded (Mulberry32) cell simulation, same conventions as the old forest-sim. Parameters map directly from `CompanyInputs` and `computeRisk` outputs (lightning rate, race probability, hardening pass, SOC containment, large-breach share) so the animation and the numbers tell the same story.
- New `CompanyCanvas` component in `src/components/breach-story.tsx`, rendered inside Section 01 above the slider blocks; colors read from `getComputedStyle` design tokens (no hardcoded colors), DPR-aware, resized with its container.
- `requestAnimationFrame` loop, paused when off-screen (IntersectionObserver) and when `prefers-reduced-motion` is set (then it renders one static annotated frame instead).
- Purely visual layer: the existing race funnels, metrics, and formulas stay unchanged and remain the source of truth; the canvas is an illustration of them, labeled as such ("illustrative replay of the model, not a second simulation").
- Mobile: canvas scales to full width, reduced cell count for performance.

## Verification

- Playwright at desktop 1280 and mobile 384: canvas renders, cells ignite and get extinguished, moving the patch-speed and SOC sliders visibly changes behavior, no console errors, build OK.
- Determinism check: same seed + same inputs → identical frame sequence (bun script).
