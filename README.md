# Breach Fire Explained

Build a single-page interactive explainer in the style of a Veritasium video:

"The Forest Fire of Cyber Breaches — why one breach can outweigh a thousand".

Tone: curious, playful, honest. Each section starts with a question,

lets the reader guess or play, then reveals the answer. Clean, light design,

large type, lots of white space, smooth animations, works on mobile.

Use React + Tailwind + Recharts (or D3) + canvas for the simulation.

No backend; all data below is embedded.



SECTION 1 — "Guess the average"

- Two side-by-side panels: "Normal world" (heights of people, normal

  distribution mean 170 cm, sd 10) and "Breach world" (sizes of US healthcare

  hacking breaches, sampled from the empirical distribution below).

- Button "Draw 10 more" and "Draw 1,000". Show each draw as a dot and a

  running-average line. In the breach world, the average should jump whenever

  a giant appears. Caption reveal: "In heavy-tailed worlds, the average never

  settles. One event can outweigh everything before it."

- Breach sampling: use this complementary cumulative distribution

  (US healthcare hacking breaches 2016–2026, 4,633 breaches, minimum 500 people):

  share of breaches >= 500: 100%; >= 100,000: 15.3%; >= 300,000: 7.5%;

  >= 1,000,000: 2.7%; >= 3,000,000: 0.82%; >= 10,000,000: 0.17%;

  >= 30,000,000: 0.043%; >= 100,000,000: 0.022%.

  Interpolate log-linearly between points; cap at 192,700,000.



SECTION 2 — "Grow your own forest fire" (the core interactive)

- Canvas grid ~120x120 cells (smaller on mobile). Cell states: empty, tree

  (unpatched system), patched tree, burning.

- Each tick: empty -> tree with probability g ("new unpatched systems");

  tree -> patched with probability r ("rain = patching"); lightning hits

  random cells at rate L ("CVEs published"); lightning ignites only

  unpatched trees; fire spreads to 4 neighbours (including patched trees,

  representing lateral movement); burning -> empty next tick.

- "Shared suppliers" slider S (0–5): creates S hub nodes, each linked to 40

  random trees. If any linked tree burns, all trees linked to that hub ignite

  (draw thin lines from the hub when it fires). Label it "one lightning,

  many fires (like MOVEit)".

- Sliders: Lightning (CVEs) x1 to x12, Growth, Rain (patching), Shared suppliers.

  Presets: "2025", "AI flood with rain (x12 lightning, high rain)",

  "AI flood, no rain", "One shared supplier".

- Side panel, live: fires so far, largest fire, share of all burned area

  from the top 1% of fires, and a log-log histogram of fire sizes with a

  fitted slope (simple MLE: alpha = 1 + n / sum(ln(size/min_size))).

- Reveal captions: "12x more lightning barely matters if it rains."

  "A single shared supplier creates the biggest fires."

  "Fire sizes form a straight line on a log-log plot: a power law."



SECTION 3 — "The real data"

- Log-log chart, x = times larger than starting size (x1 to x1000),

  y = share at least that large (100% to 0.1%), plus a dashed 1/x line.

- Series A, US healthcare, people affected (start 100,000):

  x1: 100%, x3: 48.9%, x10: 17.7%, x30: 5.4%, x100: 1.13%, x300: 0.28%, x1000: 0.14%.

- Series B, all sectors, documented losses from the EuRepoC database

  (start $10M): x1: 100%, x10: 18.8%, x100: 4.2%.

- Draggable ruler that snaps along the 1/x line and says

  "10x bigger -> about 10x rarer".

- Hover labels for named giants (people affected, year):

  Change Healthcare 192.7M (2024), Anthem 78.8M (2015), Conduent 62.2M (2025),

  DentaQuest 15.0M (2026), Welltok 14.8M (2023, MOVEit), Aflac 13.9M (2025),

  Optum360 11.5M (2019), HCA Healthcare 11.3M (2023), Premera 11.0M (2015),

  LabCorp 10.3M (2019).



SECTION 4 — "The 1% that decides everything"

- Slider "top X% of breaches" (0.1% to 20%). Show the share of all people

  affected that they account for, using the Section 1 distribution.

  Key fact to show when X = 1%: 57%. The single largest breach (Change

  Healthcare) is 22% of everyone affected since 2016.



SECTION 5 — "A thousand futures"

- Monte Carlo: simulate 1,000 futures for 2027–2031. Each year, the number

  of breaches of 1M+ people ~ Poisson(18.9 x k). Each breach size =

  1,000,000 x U^(-1/1.03), capped at 340,000,000 (US population).

- Show 1,000 small timelines (dots per year, size by breach size) and the

  share of futures with at least one 100M+ breach, updating live.

- Scenario slider for exploitation growth m (x1 to x6) and share of breaches

  that start with a vulnerability s (12% to 31%). k = (1 - s) + s x m.

  Presets: "Rain" (m=1, k=1), "Vulnpocalypse" (m=2.2, s=31%, k=1.37),

  "Extreme" (m=5.7, s=31%, k=2.46).

- Expected result to sanity-check the code: baseline ~49% of futures have a

  100M+ breach by start of 2031; vulnpocalypse ~60%; extreme ~81%.



FOOTER — "What's measured and what's modelled"

- Measured: breach sizes and counts (US healthcare, HHS registry; all

  sectors, EuRepoC). Modelled: the forest-fire simulation and the futures.

- Note: "Breach numbers are US healthcare only. Vulnerabilities start only

  12–31% of breaches; phishing and stolen passwords cause most of the rest."

- Link back to the full article.

This project was built with [Lovable](https://lovable.dev).

**Live app**: https://breach-fire-explorer.lovable.app

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/e51a4405-595a-43b2-9f3d-57e46760670a).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
