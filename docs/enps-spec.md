# eNPS weekly pop-up — spec

A once-a-week employee Net Promoter Score (eNPS) prompt that feeds an in-app
analytics dashboard in **TestPlayer-v3**. Designed here first; built in the v3
session.

---

## 1. What it measures

**eNPS** = how likely players are to recommend the club/team as a place to be.

- **Question:** "How likely are you to recommend playing here to a friend?"
- **Scale:** 0–10 (single tap)
- **Optional follow-up:** "What's the main reason for your score?" (one line, free text)
- **Score formula:** `eNPS = %Promoters (9–10) − %Detractors (0–6)`
  - Passives (7–8) count toward response totals but not the score.
  - Range: −100 to +100.

---

## 2. Pop-up behaviour

| Rule | Detail |
| ---- | ------ |
| Frequency | Once per player per **7-day window** |
| Trigger | On login/app open, check "answered in last 7 days?" — if no, show it |
| Dismissible | Yes, but re-prompts on next open until answered that week |
| After answer | Don't show again until the next weekly window |
| Time to complete | One tap for the score; comment optional |

**Weekly window:** simplest is a rolling 7 days from each player's last response.
(Alternative: a fixed club-wide week, e.g. every Monday — decide at build time;
rolling is less naggy and recommended.)

---

## 3. Data model

Each response stored as:

```
enps_response {
  id
  player_id
  score        // 0–10
  comment      // nullable, string
  created_at   // timestamp
}
```

That's all that's needed — the dashboard derives everything else.

---

## 4. In-app analytics dashboard

A new "eNPS" view (admin/coach-visible). Shows:

- **Current eNPS score** (big number, with the −100…+100 context)
- **Trend line** — eNPS by week over time
- **Response rate** — how many of the squad answered this week
- **Distribution** — count of Promoters / Passives / Detractors
- **Latest comments** — the free-text reasons, most recent first

Derived on read from the `enps_response` rows — no separate analytics store.

---

## 5. Open questions (decide at build time)

1. **Who sees the dashboard?** Coaches/admins only, or all players? (Recommend
   admins only — comments can be candid.)
2. **Anonymous comments?** eNPS is often more honest anonymised. Do we show
   `player_id` against a comment, or aggregate only? (Recommend aggregate /
   anonymous comments.)
3. **Rolling 7 days vs fixed club week** (see §2). Recommend rolling.

---

## 6. Build notes

- Front-end: a small modal component gated by a "last answered" check
  (localStorage for instant gate + server timestamp as source of truth).
- Back-end: one table + two endpoints (`POST /enps`, `GET /enps/summary`).
- Fits the same deploy pipeline — no extra infrastructure.
