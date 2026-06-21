# Test Player — Scoring V2 & Home-Screen Spec

**Status:** design draft for review. Written to drop into `foxitc/TestPlayer-v3`
(team PWA + dashboard) once Ian signs off. Nothing here is built yet.

**Decisions already taken (Ian, this thread):**
- The **51% hospitality signal is a *weighted blend*** of guest voice + manager
  judgment + peer recognition (not a single source). See §3.
- We **design here first** — this doc is the spec; implementation happens in
  `TestPlayer-v3`.

**Companion docs:** `docs/test-player-backlog.md` (the full bug/decision/philosophy
log). This spec turns §0–§3 of that backlog into something buildable.

---

## 1. The spine (why V2 exists)

Everything in V1 measures the **49% — technical execution** (dry ASPH, sides
attachment, premium wine, mains volume, productivity/hour, desserts). All real,
all kept. But in Danny Meyer's terms that's *service* — the monologue, how well
the task was done. It measures none of the **51% — hospitality**, the dialogue:
how the guest actually *felt*.

> A Test Player is the person with the highest **hospitality quotient who also
> executes well** — not the highest dessert-attachment rate.

So V2 makes the headline score, and promotion up the cricket tiers, an explicit
**51/49 blend** — a "hospitalitocracy." People rise because they embody the
culture, not because they ring the till hardest.

**Design discipline that gates every choice below:** does this make the person
feel **seen, or surveilled**? The app must read like *a good mentor noticing
you*, not a dashboard scoring you. The philosophy stays **louder than the
scoreboard**.

---

## 2. The score, top to bottom

```
TP Score (0–100)  =  ( 0.49 × Execution )  +  ( 0.51 × Hospitality )   ← then gated
                                                                          by §6
```

Both halves are normalised **0–100 against an anonymised peer group**, not against
an absolute target. (Peer-group benchmarking is also the commercial moat — §5 of
the backlog — so the normalisation engine is shared with the dashboard.)

The **same blend drives tier promotion**: tier movement reads the 51/49 TP Score
over a rolling window, not raw execution.

### 2.1 Execution — the 49% (unchanged engine, kept)
- Source: existing `selector_metrics` (each metric already carries a `weight`).
- Each server's metric → **percentile vs peer group** → weighted sum →
  `execution_score` 0–100.
- No new data needed; this is V1's strength. Upselling *done warmly* is itself
  hospitality, so it stays — it just stops being the whole story.

### 2.2 Hospitality — the 51% (new, blended — see §3)

### 2.3 Weights are **config, not code**
`0.49 / 0.51`, the within-hospitality split (§3), and every metric weight live in
a config table so Ian can tune without a deploy. Default values below are
starting points to test, not commitments.

---

## 3. Hospitality (51%) — the weighted blend

Three sources, each normalised 0–100, then combined. **Proposed default weights
(tunable):**

| Source | Weight | Why this weight |
|---|---|---|
| **G — Guest voice** | **50%** | Guest-sourced, hardest to game, already exists free. The truest 51% signal. |
| **M — Manager judgment** | **30%** | Trusted by ops, catches what guests don't write down, but subjective → capped influence. |
| **P — Peer recognition** | **20%** | Builds culture horizontally; gameable and sparse early → lowest weight. |

```
Hospitality = 0.50·G + 0.30·M + 0.20·P
```

> ⚠️ **OPEN (Ian):** confirm the 50/30/20 split. Early on, guest attribution (G)
> will be thin until review-mining ships — see §3.4 "cold start."

### 3.1 The five emotional skills, mapped to CW language
Meyer's five hospitality skills, adapted, expressed **only** in CW language so
staff and managers rate against words they already use — never the borrowed guru
vocabulary (Lee's explicit note):

| Meyer skill (adapted) | CW value (what staff/managers see) | What it means in the room |
|---|---|---|
| Optimistic warmth | **Pull up a chair** | Read the person; listen without judgement. |
| Curiosity / intelligence | **Pull up a chair** | Notice what they're *not* saying. |
| Work ethic | **Wow** | Skill + personality lift the moment. |
| Empathy | **Own it** | Take the authority to make it right. |
| Self-awareness / integrity | **No Dickheads** | The character gate (§6). |

Sequence staff internalise: **read the person → lift the moment → hold the
authority to make it right.** Every surfaced moment names *which value was on
display* + *the life skill underneath* ("that's how you read a room anywhere").

### 3.2 G — Guest voice (the richest unused signal)
- **Inputs:** Google reviews (Griffin ~1,325 @ 4.5★, Tap & Run ~922 @ 4.6★, …) +
  per-venue NPS. Reviews overwhelmingly describe *feeling* ("made us feel so
  welcome", "remembered us") — the 51%, volunteered free, today only at venue
  level.
- **Attribution = the engineering crux.** Mirror **Clerk Mapping** (which already
  attributes *sales* to individuals): an NLP pass over each review that
  1. detects hospitality **themes** (welcome, recognition, recovery, warmth),
  2. extracts **named staff** ("Sarah was wonderful"),
  3. emits a **confidence** score.
  High-confidence named mentions attribute to the individual; low-confidence /
  unnamed roll up to **venue-level** hospitality language (still useful, and still
  feeds the "wows" venue feed).
- **NPS:** if the survey captures the server, attribute; else venue-level.
- **Anti-dispute:** contested/low-confidence attributions go to a manager
  tick/cross before they touch the score (§6 gaming control).

### 3.3 M — Manager judgment ("catch people doing it right")
- Weekly, lightweight: manager rates each server against the CW values (3.1).
- **Positive-reinforcement capture (Ian's mechanism):** anyone taps a **value** →
  writes one sentence on what was done → **manager validates tick/cross** (stops
  gaming). Validated entries feed M *and* surface on the home screen (§4) naming
  the CW value + the life skill underneath.
- Keep it bounded: manager weight is capped at 30% precisely because it's
  subjective and adds workload.

### 3.4 P — Peer recognition
- Staff flag each other for hospitality **saves** ("Martyn covered my section when
  I was drowning"). Builds culture sideways.
- Manager-validated before scoring (anti-gaming). Rate-limited per person/week so
  it can't be farmed.

**Cold-start handling:** until review-mining (G) is live, temporarily reweight to
lean on M (e.g. G 0/M 60/P 40) and show Hospitality as *"warming up"* in the UI
rather than a confident number — never present a hollow score as real.

---

## 4. Home screen — hospitality-led rework

Move from **sales gamification → hospitality coaching + sentiment celebration.**
Tiles below fold in Lee's per-tile review notes (backlog §3.1).

| # | Tile | V2 behaviour | Lee's note folded in |
|---|---|---|---|
| 1 | **Shift score** | One number + **two rings: Execution / Hospitality** + sparkline (direction). | Likes it. **Review whether the `%` sign is needed.** |
| 2 | **Coaching tip** | Banner in **CW language** — "Own it / Pull up a chair / Wow moments / No Dickheads". | **Swap copy source** off borrowed guru quotes. 🟢 |
| 3 | **Guest wows** | "**4 guests mentioned you by name today**" + the actual *words*. **Never a guest's face.** | "Is it real?" → measurement = §3.2 named mentions. Privacy: words not faces. |
| 4 | **Daily ring** | Closes on **hospitality moments** — named in a review, recognising a regular, a recovery ("the grace of the fix") — not just attachment. A **kindness streak** alongside any dessert streak. | Reframes the daily drumbeat away from pure upsell. |
| 5 | **Desserts / upsell** | Reframe to **personal best / self-reference**, not ranked vs others. | "Drive revenue **without bad language**." 🟡 |
| 6 | **Steps** | Keep as "get fit while you work" fun. **Ranking stays for now** (Ian: leave it), revisit in the gamification rethink. | Lee wanted ranking removed; Ian deferred. |
| 7 | **Lifetime guests served** | **Badge of honour.** 🟢 | Lee asked for it. |
| 8 | **Wrapped recap** | Shareable stat is *"11 guests mentioned you by name this month,"* not "you sold 340 mains." | The recognition framing. |
| 9 | **Peer recognition** | Flag a colleague for a hospitality save (feeds §3.4). | New, culture-horizontal. |
| 10 | **No Dickheads** | **Not a banner** — it gates the score (§6). | "You could be winning while being one." Must bite. |

**Sales competitions** become **occasional, clearly-framed side-quests**, not the
daily beat — so we never manufacture bad hospitality (pushing a £60 bottle on a
couple who wanted a quiet cheap night) and call it winning. The Active-Challenge /
supplier-access framing is a **separate deep conversation** (backlog §3.1) — out
of scope here.

---

## 5. The "No Dickheads" gate (so you can't win while being one)

Character isn't a tile — it's a **gate on the whole score**.

- A **validated** negative-behaviour flag (manager-confirmed, with due process —
  rare and serious) applies a **multiplier/cap** to TP Score so high execution
  can't paper over it.
- Default: an active validated flag **caps Hospitality at a low ceiling** for the
  period and blocks tier promotion. Self-awareness/integrity (the 5th skill) lives
  here.

> ⚠️ **OPEN (Ian):** the exact mechanism — hard cap vs multiplier vs threshold —
> and the due-process flow. This is sensitive; it needs your call before build.

---

## 6. Anti-gaming & privacy (non-negotiable)

- **Manager tick/cross** validates every peer flag (§3.4) and every
  "catch-doing-it-right" entry (§3.3) before it scores.
- **Guest faces never shown** anywhere. Guest *words* yes, images no.
- **Review attribution** needs a confidence threshold; disputed → manager confirm.
- **Peer flags** rate-limited per person/week.
- Every metric we add gets the discipline test: **seen, or surveilled?**

---

## 7. Data model (for TP-v3 — proposed)

New tables (names indicative). Designed to sit alongside existing
`selector_metrics`:

```
hospitality_events
  id, user_id, venue_id,
  source        ENUM(guest_review, nps, manager, peer),
  value_tag     ENUM(pull_up_a_chair, wow, own_it),   -- CW value on display
  score_delta   numeric,
  raw_text      text,                                  -- the words (review / note)
  confidence    numeric,                               -- attribution confidence (guest sources)
  status        ENUM(pending, validated, rejected),
  validated_by  user_id NULL,
  created_at, period

guest_mentions                                         -- output of review/NPS mining
  id, review_id|nps_id, source, venue_id,
  user_id NULL,                                         -- null = venue-level only
  attributed_name text, confidence numeric,
  sentiment, themes text[],
  status ENUM(pending, validated, rejected)

manager_ratings                                        -- weekly, CW-value framed
  id, user_id, week,
  pull_up_a_chair, wow, own_it numeric,                -- the 5 skills, mapped to CW
  integrity_flag boolean, notes text

peer_flags
  id, from_user, to_user, value_tag, note,
  status ENUM(pending, validated, rejected), validated_by

tp_score                                               -- materialised per period
  user_id, period,
  execution_score, hospitality_score,
  g_score, m_score, p_score,                           -- blend components, for transparency
  gate_applied boolean, tp_score
```

**New ingestion needed:** a **Google reviews connector** (+ NPS feed) into
`guest_mentions`, then the NLP attribution pass. This is the biggest new build and
the dependency for G in §3.2.

---

## 8. Build order (suggested, once in TP-v3)

1. **Config-ise the weights** (0.49/0.51, G/M/P) + `tp_score` table — makes
   everything tunable from day one.
2. **Execution score** from existing `selector_metrics` (low risk, reuses V1).
3. **Manager judgment (M)** + the catch-doing-it-right capture — fastest path to a
   *real* hospitality number, covers cold-start.
4. **Peer recognition (P)** — small, culture win.
5. **Home screen** rings + tiles (§4) against scores 1–4.
6. **Guest voice (G):** reviews connector → NLP attribution → `guest_mentions` →
   "Guest wows" tile. Highest value, highest effort — ship last, reweight up.
7. **No-Dickheads gate (§5)** — after Ian's mechanism decision.

Also in TP-v3: **fix its own copy of the productivity calc** (the
`MAX(pay_date)` window fix already landed in `selector/packages/routes.js`).

---

## 9. Still open for Ian (blocks specific pieces, not the whole spec)

1. **G/M/P weights** (§3) — confirm 50/30/20, and the cold-start reweight.
2. **No-Dickheads gate mechanism** (§5) — cap vs multiplier + due process.
3. **`%` sign on the shift score** (§4 tile 1) — keep or drop.
4. **Desserts reframe** (§4 tile 5) — confirm PB/self-reference framing.
5. **Guest-wows exact measurement + privacy confirm** (§3.2 / §4 tile 3) — what
   counts as a "mention", confirm no faces.
6. **Active-Challenge / supplier-access framing** — deliberately deferred to its
   own conversation (backlog §3.1).
