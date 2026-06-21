# Test Player — Working Backlog & Direction

Captured from Ian's and Lee's notes (the long product/philosophy thread + the app
review notes), plus the productivity-calculation investigation. This is the
single place to track what's a **bug**, what's **product direction**, and what's
**still an open decision for Ian**. Nothing here is built yet unless marked done.

Status legend: 🔴 bug · 🟡 design/decision needed · 🟢 ready to build · 💭 philosophy/framing

---

## 0. Headline reframe (the spine everything hangs off)

> "Not a service tool, but a way of being — developing oneself through the art of
> serving others." — Ian

The core tension surfaced in the thread: **everything built so far measures the
49% (technical execution — ASPH, sides, premium wine, mains, productivity per
hour). Almost nothing measures the 51% (how the guest *felt*).** Danny Meyer's
*Setting the Table* framing:

- **Service** = the monologue (how well you executed the task). The 49%.
- **Hospitality** = the dialogue (how you made the guest feel). The 51%.
- A "Test Player" should be the person with the highest **hospitality quotient who
  also executes well** — not the highest dessert-attachment rate.
- Meyer ties 51% of raises/bonuses to emotional skills → a "hospitalitocracy."
  People rise because they embody the culture, not because they ring the till hard.

**Design discipline (recurring theme):** every time we're tempted to add a metric,
ask whether it makes the person feel **seen or surveilled**. The app should feel
like *a good mentor noticing you*, not a dashboard scoring you (the "Apple hides
the tech" lesson). The philosophy must stay **louder than the scoreboard**.

---

## 1. Bugs / Engineering

### 1.1 🔴 Productivity-per-hour: high over a week, collapses over 90 days
**Reporter:** Ian (via Lee's notes). **Status:** diagnosed, fix not yet applied.

- **What it is:** `rev_per_labour_hour = SUM(net revenue) ÷ SUM(estimated labour hours)`
  over the selected window.
- **Where (this `selector` repo):**
  - `packages/routes.js:1250` — `/selector/metrics/with-averages` (dashboard figure)
  - `packages/routes.js:2457` — `/metrics/asph`
  - ⚠️ The Test Player app (`foxitc/TestPlayer-v3`) likely has its **own copy** —
    fix must be applied there too.
- **Root cause (most likely):** numerator and denominator are built from
  different sets of shifts, and the mismatch is worst on short windows:
  1. **Pay data lags sales data (primary).** Revenue filters on `datetime_sold`
     (instant); hours filter on RotaReady `pay_date` (only dated once signed
     off / pay-run). In the last 7 days, sales are fully present but recent hours
     aren't yet → hours undercounted → productivity inflated. Over 90 days the lag
     is negligible → ratio settles to its true (lower) value. Matches the symptom.
  2. **Salaried staff add lumpy hours (secondary).** Est. hours for salaried =
     `total_pay / 12.21` (`routes.js:1253`), `is_salaried = payAmount > 100`.
     Lumps on sparse dates drag the denominator down more as the window grows.
- **Confirm on the VPS (this session can't reach the DB):**
  ```sql
  SELECT 'sales' src, MAX(datetime_sold)::date AS latest FROM relay_sold_items
  UNION ALL
  SELECT 'pay'   src, MAX(pay_date)            AS latest FROM rotaready_pay;
  ```
  If `pay.latest` trails `sales.latest`, mechanism #1 is confirmed.
- **Fix options:** (a) clip the revenue window end to `MIN(MAX(pay_date), now)` so
  complete sales are never divided by incomplete hours [cleanest]; (b) exclude
  salaried staff from the per-hour denominator; (c) only count closed/complete
  days. **Decision needed before patching.**
- **Note:** the `// Pull rolling 28 days` comment at `routes.js:2074` is stale —
  the sync actually pulls **90 days** (`routes.js:2076`). Tidy while in there.

---

## 2. Scoring model — the 51/49 redesign (Selector V2)

🟡 **Biggest single design decision in the project.**

- Keep the existing upsell/execution metrics as the **49% (technical execution)** —
  they're good, and upselling done warmly *is* hospitality.
- Introduce a **51% hospitality dimension** built on Meyer's five emotional skills,
  adapted: optimistic warmth, curiosity/intelligence, work ethic, empathy,
  self-awareness/integrity.
- The same 51/49 weighting should govern **promotion up the cricket tiers**, not
  just the headline score.
- **Open decision (Ian to steer):** where do we most trust the 51% measurement to
  come from? — manager weekly judgment / guests' own words (reviews + NPS) / team
  rating each other / a blend. **This changes how the whole thing gets built.**

### 2.1 Guest sentiment — the richest unused signal
- Griffin: 1,325 Google reviews @ 4.5★; Tap & Run: 922 @ 4.6★; plus per-venue NPS.
- Reviews overwhelmingly describe *feeling* ("made us feel so welcome", "remembered
  us") — the 51%, volunteered free, currently only at venue level.
- **Idea:** attribute reviews to individuals (like Clerk Mapping attributes sales)
  → a direct, guest-sourced hospitality measure per server. Even un-attributed,
  mine review language for hospitality themes per venue.

---

## 3. Team app — home screen rework (hospitality-led)

💭/🟡 Move from **sales gamification → hospitality coaching + sentiment celebration.**

- **Daily ring closes on hospitality moments, not just attachment** — e.g. a guest
  naming you in a review, recognising a regular, a recovery when something went
  wrong (Meyer's gold standard: the grace of the fix). A "kindness streak" as much
  as a dessert streak.
- **"Wrapped"-style recap:** the shareable stat is "11 guests mentioned you by
  name this month," not "you sold 340 mains."
- **Peer recognition:** let staff flag each other for hospitality saves ("Martyn
  covered my section when I was drowning") — builds culture horizontally.
- **Sales competitions become occasional, clearly-framed side-quests**, not the
  daily drumbeat — to avoid manufacturing bad hospitality (pushing a £60 bottle on
  a couple who wanted a quiet cheap night) and calling it winning.

### 3.1 Specific tile notes from Lee's app review
| Tile | Lee's note | Action |
|---|---|---|
| Shift score | Likes single number + two rings (Execution / Hospitality). "Does it need the % sign?" Likes the sparkline direction. | 🟢 minor: review % sign |
| Coaching tip | Likes the banner, **but use our language not borrowed guru quotes** — "Own it / Pull up a chair / Wow moments / No Dickheads." | 🟢 swap copy source |
| Steps | **Remove the ranking** (drives running up/down to hit #1). Keep as "get fit while you work" fun only. | 🟡 *Ian: leave for now*, revisit with gamification rethink |
| Guest wows | "How is this measured? Is it real?" Likes the value word; **can't use guests' faces.** "4 mentioned you today" = the good version (proof of recognition). | 🟡 define measurement + privacy |
| Desserts | How to drive revenue here **without bad language**? Self-reference / PB better than ranked. | 🟡 reframe to PB/self |
| Active Challenge | Is this where **suppliers buy access** with competitions? Likes it but nervous — "high-stakes competition vs low-stakes comparison." Wants a deep conversation on framing without an overselling dynamic. | 🟡 deep discussion |
| Your division | Understood, fine. | 🟢 |
| No Dickheads | Can't be a banner — but **nothing currently leans into it; you could be winning while being one.** Complex discussion. | 🟡 design how it gates the score |
| Lifetime guests served | Should appear as a **badge of honour**. | 🟢 add badge |

### 3.2 🟡 "Catch people doing it right" — positive-reinforcement feedback
Ian's proposed mechanism (wants a view on it):
- Tap on a **value** → write a short sentence describing what was done →
  **manager validates with tick/cross** to stop gaming.
- Goal: reinforce positive behaviour to get more of it. Names the **CW value** on
  display ("That was a brilliant *Pull Up a Chair* — you caught what they weren't
  saying") and the **life skill underneath** ("that's how you read a room anywhere").

---

## 4. Commercial tab (Ian's dashboard request)

🟡 "If the product is going to fly we need to easily show decision makers the value.
It has to feel like you're missing out on company profit if you don't do this."

Requested contents:
1. **Believability list** — what leaders need to see to trust implementation is
   possible (start a running list of requirements + how we help).
2. **Sales improvement as rings close** — show individual → operating unit →
   group ("the big sexy number").
3. **Interactive cost-base inputs** — a couple of open entry boxes so they add their
   own cost base → see company contribution. Makes it feel interactive.
4. **Additional wins to surface:**
   - *Productivity:* fewer server hours because monitored servers are more driven.
   - *Retention:* the best stay longer because they're recognised.
5. **Commercial relationships model:** if the OD does a commercial deal, feed it
   into a competition and show the financial result (worked example).
6. **Team cost / pay investment:** Ian has spreadsheet work — how much pay-improvement
   investment creates the best "premium players" result; **goal is suppliers
   mitigating as much of that cost as possible.** Ian's view: a big hike in pay rate
   is unnecessary.

> Build location: the Test Player dashboard (`TestPlayer-v3`) — needs that repo added.

---

## 5. Commercialisation / go-to-market

- **The moat = a large database of operators** where each sees performance against
  an **anonymised peer group.** Copying the app doesn't replicate the benchmark.
- **The score must be duplicable across groups** so cross-company comparison works.
- **First two target companies:** **Bosco Pizza** and **Rockfish** (Ian has strong
  links with both owners). Task: can we apply the TP logic to *their* offer?
- **Positioning:** small & beautiful first, until the collective voice is loud
  enough to be heard. "Great hospitality IS great business." Avoid the trap of
  converting institutions on their (P&L) terms and watching the mission get sanded
  down. Arm the believers rather than convert the non-believers (for now).
- **Recognised credential ambition:** "I'm a Test Player, employ me!" — a level
  usable in recruitment/applications across careers.

---

## 6. Mission, language & values (the framing staff actually read)

💭 Largely settled in the thread; pulled together here.

**Three concentric circles (Ian's own):** **Team → Table → Community** — in that
order ("you can't pour from an empty glass"). Get all three turning and it compounds.

**CW values as a single sequence (not three posters):**
- **Pull up a chair** = *perceive* — listen/learn without judgement (the kindness
  engine; also exactly the posture the disadvantaged-access hiring needs).
- **Wow** = *act with creativity* — skills + personality lift the moment.
- **Own it** = *take authority* — licence to act, big splash or small recovery.
  The thing freehold-machine operators structurally can't give → the competitive
  moat disguised as a value.
- **No Dickheads** = the character gate (see 3.1 — must actually affect the score).

> Sequence: **read the person → lift the moment → hold the authority to make it
> right.** When TP surfaces a moment, name which value was on display + the life
> skill underneath.

**Open question (Ian to test with team):** of the three, which is hardest to *do*?
Hypothesis: **Own it** — people only believe the authority is real after they've
used it once and weren't punished. So TP's first job may be catching & celebrating
early "Own it" moments.

**Elevator pitch — riffs drafted, not yet chosen:**
> "Test Player is our way of saying we're at the top of our game. Hospitality isn't
> a job you do — it's a skill you master and keep for life. We read the person, lift
> the moment, and own it. We make people want to come back — and we make our people
> better wherever they go next. One table at a time."

Through-lines to protect in whichever wins: *top of the game · the hard thing is
the point · yours to keep for life · leave them better.* Ian testing with the team
before we cut to one.

---

## 7. Social mission — disadvantaged-access hiring partner (from day one)

💭 Treated as core, not CSR. Proves the mission is real, tests "nurture over nature"
at its hardest, and gives a story P&L-machine operators structurally can't tell.

Shortlist surfaced (verify live before approaching — these orgs change):
- **Only A Pavement Away** — best fit; hospitality-built, bridges vulnerable /
  homeless / prison-leaver / veteran candidates, 12 months post-placement support.
  Obvious first conversation for a small-and-beautiful pilot.
- **The Clink Charity** — restaurants inside prisons; trained graduates pre-release.
- **Hotel School** — 10-week programme for people who've experienced homelessness;
  closest philosophical cousin.

---

## 8. Open decisions for Ian (the blockers)

1. **Productivity fix approach** (§1.1) — confirm with the coverage query, then pick
   clip-window vs exclude-salaried vs complete-days-only.
2. **Where the 51% is measured** (§2) — managers / guests / peers / blend. Gates the
   entire scoring rebuild.
3. **Guest-wows measurement + privacy** (§3.1) — what counts, and confirm no guest
   faces.
4. **Active Challenge / supplier access framing** (§3.1) — low-stakes comparison vs
   high-stakes competition; avoid the overselling dynamic.
5. **How "No Dickheads" affects the score** (§3.1) — so you can't win while being one.
6. **Pay-investment vs supplier-funding model** (§4.6) — review Ian's spreadsheet.

---

## 9. Repo / environment note
- This `selector` repo contains the productivity calc + deploy scripts. The **Test
  Player app source is in `foxitc/TestPlayer-v3`** (separate VPS `51.75.142.7`),
  **not yet cloned into this session** — needed for the dashboard/commercial-tab and
  team-app work (and to fix the second copy of the productivity calc).
- Deploys run from a machine with SSH access to the VPS (`bash deploy.sh`); this
  cloud session's network policy blocks SSH to the box.
