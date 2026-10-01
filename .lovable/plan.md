# Forest fire explainer corrections

## Changes
- Clarify that lightning represents a newly published vulnerability and only ignites unpatched systems.
- Track every lightning strike and show live fires started per 100 strikes in the Section 2 statistics.
- Add the requested evidence caption beneath the Section 2 presets.
- Tune and deterministically test the four forest presets over an approximately 30-second run so their relative outcomes match the story.
- Update the Section 5 subtitle to explain the seven-million-person drawing threshold.
- Verify seeded Rain, Vulnpocalypse, and Extreme results are approximately 49%, 60%, and 81%.

## Technical details
- Extend the local simulation statistics with a lightning-strike count; no backend or uploaded data will be added.
- Keep seeded random generation so scenario comparisons remain reproducible.
- Validate compilation and exercise the updated controls in desktop and mobile preview sizes.
