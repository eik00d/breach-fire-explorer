<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

- Keep all interactive scientific simulations deterministic when seeded, so visual comparisons and editorial claims remain reproducible.
- Keep uploaded source datasets out of the client bundle; embed only reviewed aggregate facts needed by the story.
- Section 01 canvas animation lives in src/lib/company-sim.ts (deterministic seeded cell sim); it is an illustrative replay driven by computeRisk outputs — the calculator formulas stay the only source of numbers, never read values back from the sim.
- Model reach, incidents, any-size loss and reported loss separately; preserve the old reported calibration in the unsaturated regime and label probability caps at extreme settings.
- Non-vulnerability breach channels (credentials, phishing, other) are calibrated as fixed multiples of the default-settings vulnerability rate for the selected size; keep the vulnerability channel's numbers independent of them, because the defaults must reproduce the observed initial-access mix.
- Apply channel-specific threat multipliers to credential and phishing lightning rates before their defence gates, with legacy-input fallbacks of one; the canvas inherits those rates from computeRisk to preserve calibration and a single source of truth.
- Store device management as one shared input rendered in both relevant channels; normalize endpoint effectiveness against default coverage and apply all per-channel defence factors in computeRisk before common hardening and SOC gates.
