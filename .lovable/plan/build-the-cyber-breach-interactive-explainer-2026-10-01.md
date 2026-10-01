# Build the cyber-breach interactive explainer

## Experience
- Replace the placeholder with a single scrolling story in a crisp editorial-science style: large question-led headings, generous white space, warm fire accents, cool data accents, and subtle motion.
- Add a compact progress rail so readers can see where they are across the five experiments.
- Keep every interaction touch-friendly and legible on the current mobile viewport as well as desktop.

## Interactive sections
1. **Guess the average** — paired live charts for a normal distribution and the supplied heavy-tail distribution, with 10/1,000 draw controls, running averages, and giant-event callouts.
2. **Grow your own forest fire** — an efficient canvas simulation with growth, patching, lightning, spread, shared-supplier hubs, presets, live statistics, and a log-log fire-size chart with fitted power-law slope.
3. **The real data** — a responsive log-log comparison chart, 1/x reference line, draggable/snapping ruler, and labelled giant breaches.
4. **The 1% that decides everything** — a top-share slider backed by an embedded deterministic breach-size population, calibrated to show the supplied 1% and largest-breach facts.
5. **A thousand futures** — deterministic-seeded Monte Carlo simulation with 1,000 compact timelines, scenario controls, and live 100M+ probability.
6. **Methods footer** — clearly separate measured data from modelled outputs and include the requested article link as a labelled placeholder when no URL is supplied.

## Technical details
- Use React state/hooks, the existing Recharts package, and a dedicated canvas component for the fire grid and futures raster.
- Embed only the aggregate data and public named incidents required by the story; no backend or uploaded raw files will ship with the page.
- Use seeded pseudo-randomness where reproducibility helps, while preserving interactive redraw/reset behavior.
- Define semantic design tokens and motion in the global stylesheet, preserve reduced-motion preferences, and add complete route metadata.
- Verify the current build signal and inspect the page at desktop and mobile sizes, including active controls and canvases.
