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
- Draw a browser-random canvas seed on mount and explicit Restart only; reuse it for settings changes so comparisons preserve the same luck without changing the model.
- Keep uploaded source datasets out of the client bundle; embed only reviewed aggregate facts needed by the story.
- Section 01 canvas animation lives in src/lib/company-sim.ts (deterministic seeded cell sim); it is an illustrative replay driven by computeRisk outputs — the calculator formulas stay the only source of numbers, never read values back from the sim.
- Model reach, incidents, any-size loss and reported loss separately; preserve the old reported calibration in the unsaturated regime and label probability caps at extreme settings.
- Non-vulnerability breach channels are calibrated as fixed multiples of the default-settings vulnerability rate for the selected size; keep the vulnerability channel independent so the default total remains IRIS-calibrated.
- Apply channel-specific threat multipliers to credential and phishing lightning rates before their defence gates, with legacy-input fallbacks of one; the canvas inherits those rates from computeRisk to preserve calibration and a single source of truth.
- Store device management as one shared input rendered in both relevant channels; normalize endpoint effectiveness against default coverage and apply all per-channel defence factors in computeRisk before common hardening and SOC gates.
- Resolve master and advanced AI amplifiers centrally in company-risk; isolate race, credential, phishing and post-entry effects, and use shared pure scenario transforms for comparison cards and applied settings so current defences are preserved.
- Implement Switch with a native checkbox and switch role, like the native Slider; avoid hook-based optimized control dependencies that can use a mismatched React dispatcher in preview.

- Keep replay-state colors in dedicated semantic tokens and pair them with distinct legend shapes; do not repurpose chart colors for unrelated canvas outcomes.
- Treat wall crossing as a visual-only seeded permission per large fire, never retry failed permission, and retain the large outcome inside its origin segment; wall feedback must identify the actual crossed or blocked edge.

- Solve default exposure from annual IRIS probability targets at full precision; published rounded exposures are display values, not arithmetic inputs.
- Keep pretexting separate from phishing in maths and replay; only its modest Identity multiplier and common hardening/SOC gates apply, never email, training, EDR or phishing AI.
- Model supplier-held data as an external channel controlled only by supplier security and governance-derived size, bypassing local defence gates; render it outside network cells so local walls and SOC never appear to stop it.
- Derive canvas channel expectations from simParams and public-event shares from computeRisk; preserve residual spark records separately from cell availability so every residual event is visible.
