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
- Expose reach and conditional hardening separately while preserving the calibrated combined pass probability; this keeps existing risk scenarios unchanged.
