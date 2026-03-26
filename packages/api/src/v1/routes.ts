// ================================================================
// TEST PLAYER — API Routes (Express)
// All routes that power the Test Player front end and TV display.
// ================================================================

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { randomUUID } from 'crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { db } from '../config/database.js';
import { env } from '../config/env.js';
import { runSelectorForWeek } from '../services/selectorRunner.js';
import { encryptCredentials, decryptCredentials } from '../connectors/base.js';
import { getConnector } from '../connectors/registry.js';

const router = Router();
type Row = Record<string, unknown>;

// ----------------------------------------------------------------
// HELPERS
// ----------------------------------------------------------------
function ok(res: Response, data: unknown, status = 200) {
  res.status(status).json({ data, error: null });
}
function err(res: Response, message: string, code = 400) {
  res.status(code).json({ data: null, error: { message } });
}

const weekStr = () => {
  const today = new Date();
  const day = today.getDay();
  const sunday = new Date(today);
  sunday.setDate(today.getDate() - (day === 0 ? 0 : day));
  return sunday.toISOString().split('T')[0]!;
};

// ----------------------------------------------------------------
// AUTH
// ----------------------------------------------------------------
router.post('/auth/login', async (req, res, next) => {
  try {
    const { email, password } = z.object({
      email: z.string().email(),
      password: z.string().min(1),
    }).parse(req.body);

    const result = await db.query<Row>(
      `SELECT id, email, password_hash, first_name, last_name, role, venue_id, is_active
       FROM platform_users WHERE email = $1`,
      [email.toLowerCase()],
    );
    const user = result.rows[0];
    const hash = user?.['password_hash'] as string ?? '$2a$12$invalid';
    const valid = await bcrypt.compare(password, hash);

    if (!user || !user['is_active'] || !valid) {
      return err(res, 'Invalid email or password', 401);
    }

    await db.query(`UPDATE platform_users SET last_login = NOW() WHERE id = $1`, [user['id']]);

    const token = jwt.sign(
      { userId: user['id'], email: user['email'], role: user['role'], venueId: user['venue_id'] },
      env.JWT_SECRET,
      { expiresIn: '7d' },
    );

    return ok(res, {
      token,
      user: { id: user['id'], email: user['email'], firstName: user['first_name'],
               lastName: user['last_name'], role: user['role'], venueId: user['venue_id'] },
    });
  } catch (e) { next(e); }
});

// Auth middleware
function auth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return err(res, 'Unauthorized', 401);
  try {
    const payload = jwt.verify(header.slice(7), env.JWT_SECRET) as {
      userId: string; email: string; role: string; venueId: string | null;
    };
    (req as Request & { user: typeof payload }).user = payload;
    next();
  } catch { return err(res, 'Invalid token', 401); }
}

function adminOnly(req: Request, res: Response, next: NextFunction) {
  const user = (req as Request & { user?: { role: string } }).user;
  if (!user || user.role !== 'admin') return err(res, 'Admin access required', 403);
  next();
}

// ----------------------------------------------------------------
// VENUES
// ----------------------------------------------------------------
router.get('/venues', auth, async (req, res, next) => {
  try {
    const result = await db.query<Row>(
      `SELECT v.*, COUNT(tm.id) AS member_count
       FROM venues v
       LEFT JOIN team_members tm ON tm.venue_id = v.id AND tm.is_active = true
       WHERE v.is_active = true
       GROUP BY v.id ORDER BY v.name`,
    );
    ok(res, result.rows);
  } catch (e) { next(e); }
});

// ----------------------------------------------------------------
// SQUAD (team members)
// ----------------------------------------------------------------
router.get('/squad', auth, async (req, res, next) => {
  try {
    const user = (req as Request & { user: { venueId: string | null; role: string } }).user;
    const venueId = req.query['venueId'] as string | undefined ?? user.venueId ?? undefined;

    const result = await db.query<Row>(
      `SELECT tm.*, v.name AS venue_name, v.short_name AS venue_short_name,
              ss.total_score, ss.tier, ss.programme_status, ss.score_change,
              ss.assessment_score, ss.epos_score, ss.operational_score,
              ss.coaching_narrative, ss.rank_in_venue
       FROM team_members tm
       JOIN venues v ON v.id = tm.venue_id
       LEFT JOIN selector_scores ss ON ss.team_member_id = tm.id AND ss.week_ending = $2
       WHERE tm.is_active = true
         AND ($1::uuid IS NULL OR tm.venue_id = $1)
       ORDER BY ss.rank_in_venue ASC NULLS LAST, tm.last_name, tm.first_name`,
      [venueId ?? null, weekStr()],
    );
    ok(res, result.rows);
  } catch (e) { next(e); }
});

router.post('/squad', auth, adminOnly, async (req, res, next) => {
  try {
    const body = z.object({
      venueId:      z.string().uuid(),
      firstName:    z.string().min(1),
      lastName:     z.string().min(1),
      role:         z.string().optional(),
      department:   z.enum(['Kitchen','FOH','Bar','Management']).optional(),
      avatarColor:  z.string().regex(/^#[0-9a-fA-F]{6}$/).default('#fd6f53'),
      eposId:       z.string().optional(),
      rotaId:       z.string().optional(),
      joinedAt:     z.string().optional(),
    }).parse(req.body);

    const initials = (body.firstName[0]! + body.lastName[0]!).toUpperCase();
    const result = await db.query<Row>(
      `INSERT INTO team_members
         (id, venue_id, first_name, last_name, display_name, role, department,
          avatar_initials, avatar_color, epos_id, rota_id, joined_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING *`,
      [randomUUID(), body.venueId, body.firstName, body.lastName,
       `${body.firstName} ${body.lastName}`, body.role ?? null,
       body.department ?? null, initials, body.avatarColor,
       body.eposId ?? null, body.rotaId ?? null, body.joinedAt ?? null],
    );
    ok(res, result.rows[0], 201);
  } catch (e) { next(e); }
});

// ----------------------------------------------------------------
// MANAGER ASSESSMENT
// ----------------------------------------------------------------
router.get('/assessments', auth, async (req, res, next) => {
  try {
    const venueId = req.query['venueId'] as string | undefined;
    const week = (req.query['weekEnding'] as string | undefined) ?? weekStr();

    const result = await db.query<Row>(
      `SELECT ma.*, tm.display_name, tm.avatar_initials, tm.avatar_color,
              tm.role, tm.department, v.name AS venue_name
       FROM manager_assessments ma
       JOIN team_members tm ON tm.id = ma.team_member_id
       JOIN venues v ON v.id = ma.venue_id
       WHERE ma.week_ending = $1
         AND ($2::uuid IS NULL OR ma.venue_id = $2)
       ORDER BY tm.display_name`,
      [week, venueId ?? null],
    );
    ok(res, result.rows);
  } catch (e) { next(e); }
});

// GET assessment form for a member — returns existing or empty
router.get('/assessments/:memberId', auth, async (req, res, next) => {
  try {
    const week = (req.query['weekEnding'] as string | undefined) ?? weekStr();
    const result = await db.query<Row>(
      `SELECT * FROM manager_assessments WHERE team_member_id = $1 AND week_ending = $2`,
      [req.params['memberId'], week],
    );
    ok(res, result.rows[0] ?? null);
  } catch (e) { next(e); }
});

// POST / upsert assessment — triggers selector re-run for this member
router.post('/assessments', auth, async (req, res, next) => {
  try {
    const user = (req as Request & { user: { userId: string } }).user;
    const body = z.object({
      teamMemberId:       z.string().uuid(),
      venueId:            z.string().uuid(),
      weekEnding:         z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
      productConfidence:  z.number().min(1).max(5),
      guestWarmth:        z.number().min(1).max(5),
      tableReading:       z.number().min(1).max(5),
      valuesAlignment:    z.number().min(1).max(5),
      coachingTier:       z.enum(['could-say','should-say','have-to']),
      coachingNote:       z.string().optional(),
      dontSayFlags:       z.array(z.string()).optional(),
    }).parse(req.body);

    // Weighted assessment score (product confidence and warmth weighted higher)
    const assessmentScore = (
      body.productConfidence * 1.3 +
      body.guestWarmth       * 1.3 +
      body.tableReading      * 1.0 +
      body.valuesAlignment   * 1.4
    ) / (1.3 + 1.3 + 1.0 + 1.4) / 5 * 100;

    const result = await db.query<Row>(
      `INSERT INTO manager_assessments
         (id, team_member_id, venue_id, assessor_id, week_ending,
          product_confidence, guest_warmth, table_reading, values_alignment,
          coaching_tier, coaching_note, dont_say_flags, assessment_score)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       ON CONFLICT (team_member_id, week_ending) DO UPDATE
       SET product_confidence = EXCLUDED.product_confidence,
           guest_warmth       = EXCLUDED.guest_warmth,
           table_reading      = EXCLUDED.table_reading,
           values_alignment   = EXCLUDED.values_alignment,
           coaching_tier      = EXCLUDED.coaching_tier,
           coaching_note      = EXCLUDED.coaching_note,
           dont_say_flags     = EXCLUDED.dont_say_flags,
           assessment_score   = EXCLUDED.assessment_score,
           assessor_id        = EXCLUDED.assessor_id
       RETURNING *`,
      [randomUUID(), body.teamMemberId, body.venueId, user.userId, body.weekEnding,
       body.productConfidence, body.guestWarmth, body.tableReading, body.valuesAlignment,
       body.coachingTier, body.coachingNote ?? null,
       body.dontSayFlags ?? null, Math.round(assessmentScore * 100) / 100],
    );

    ok(res, result.rows[0], 201);
  } catch (e) { next(e); }
});

// ----------------------------------------------------------------
// SCORES & LEAGUE
// ----------------------------------------------------------------
router.get('/scores', auth, async (req, res, next) => {
  try {
    const week = (req.query['weekEnding'] as string | undefined) ?? weekStr();
    const venueId = req.query['venueId'] as string | undefined;

    const result = await db.query<Row>(
      `SELECT ss.*, tm.display_name, tm.first_name, tm.avatar_initials, tm.avatar_color,
              tm.role, tm.department, v.name AS venue_name, v.short_name
       FROM selector_scores ss
       JOIN team_members tm ON tm.id = ss.team_member_id
       JOIN venues v ON v.id = ss.venue_id
       WHERE ss.week_ending = $1
         AND ($2::uuid IS NULL OR ss.venue_id = $2)
       ORDER BY ss.rank_in_venue ASC NULLS LAST`,
      [week, venueId ?? null],
    );
    ok(res, result.rows);
  } catch (e) { next(e); }
});

router.get('/league', auth, async (req, res, next) => {
  try {
    const week = (req.query['weekEnding'] as string | undefined) ?? weekStr();
    const result = await db.query<Row>(
      `SELECT vs.*, v.name AS venue_name, v.short_name
       FROM venue_scores vs
       JOIN venues v ON v.id = vs.venue_id
       WHERE vs.week_ending = $1
       ORDER BY vs.league_position ASC`,
      [week],
    );
    ok(res, result.rows);
  } catch (e) { next(e); }
});

// ----------------------------------------------------------------
// THE SELECTOR — run on demand
// ----------------------------------------------------------------
router.post('/selector/run', auth, adminOnly, async (req, res, next) => {
  try {
    const { weekEnding } = z.object({ weekEnding: z.string().optional() }).parse(req.body);
    const result = await runSelectorForWeek(weekEnding);
    ok(res, result);
  } catch (e) { next(e); }
});

// ----------------------------------------------------------------
// CONNECTORS
// ----------------------------------------------------------------
router.get('/connectors', auth, adminOnly, async (req, res, next) => {
  try {
    const result = await db.query<Row>(
      `SELECT id, name, provider, base_url, auth_type, auth_config, is_active,
              last_sync_at, last_sync_status, last_sync_message,
              (credentials_encrypted IS NOT NULL) AS has_credentials,
              created_at
       FROM connectors ORDER BY name`,
    );
    ok(res, result.rows);
  } catch (e) { next(e); }
});

router.post('/connectors', auth, adminOnly, async (req, res, next) => {
  try {
    const body = z.object({
      name:       z.string().min(1),
      provider:   z.string().min(1),
      baseUrl:    z.string().url(),
      authType:   z.enum(['api_key','bearer','basic']),
      authConfig: z.record(z.unknown()).default({}),
    }).parse(req.body);

    const result = await db.query<Row>(
      `INSERT INTO connectors (id, name, provider, base_url, auth_type, auth_config)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, name, provider, is_active, created_at`,
      [randomUUID(), body.name, body.provider, body.baseUrl, body.authType, JSON.stringify(body.authConfig)],
    );
    ok(res, result.rows[0], 201);
  } catch (e) { next(e); }
});

router.post('/connectors/:id/credentials', auth, adminOnly, async (req, res, next) => {
  try {
    const creds = z.record(z.string()).parse(req.body);
    const encrypted = encryptCredentials(creds);
    await db.query(`UPDATE connectors SET credentials_encrypted = $1 WHERE id = $2`, [encrypted, req.params['id']]);
    ok(res, { success: true, message: 'Credentials stored securely' });
  } catch (e) { next(e); }
});

router.post('/connectors/:id/test', auth, adminOnly, async (req, res, next) => {
  try {
    const connResult = await db.query<Row>(`SELECT * FROM connectors WHERE id = $1`, [req.params['id']]);
    const conn = connResult.rows[0];
    if (!conn) return err(res, 'Connector not found', 404);

    const credentials = conn['credentials_encrypted']
      ? decryptCredentials(conn['credentials_encrypted'] as string)
      : {};

    const connector = getConnector({
      id: conn['id'] as string,
      provider: conn['provider'] as string,
      baseUrl: conn['base_url'] as string,
      authType: conn['auth_type'] as 'api_key' | 'bearer' | 'basic',
      authConfig: conn['auth_config'] as Record<string, unknown>,
      credentials,
    });

    const start = Date.now();
    const result = await connector.testConnection();

    await db.query(
      `UPDATE connectors SET last_sync_status = $1, last_sync_message = $2, last_sync_at = NOW() WHERE id = $3`,
      [result.success ? 'success' : 'failed', result.message, conn['id']],
    );

    ok(res, result);
  } catch (e) { next(e); }
});

// ----------------------------------------------------------------
// TV DISPLAY — public endpoint, token authenticated
// ----------------------------------------------------------------
router.get('/display/:token', async (req, res, next) => {
  try {
    const tokenResult = await db.query<Row>(
      `SELECT dt.*, v.id AS venue_id, v.name AS venue_name, v.short_name
       FROM display_tokens dt
       JOIN venues v ON v.id = dt.venue_id
       WHERE dt.token = $1 AND dt.is_active = true`,
      [req.params['token']],
    );
    if (!tokenResult.rows[0]) return err(res, 'Invalid display token', 401);

    const { venue_id: venueId, venue_name: venueName, short_name: venueShort, theme_config: themeConfig } = tokenResult.rows[0] as {
      venue_id: string; venue_name: string; short_name: string; theme_config: Record<string, unknown>;
    };

    const week = weekStr();

    // Squad scores
    const scores = await db.query<Row>(
      `SELECT ss.total_score, ss.tier, ss.programme_status, ss.score_change,
              ss.rank_in_venue, ss.coaching_narrative,
              tm.display_name, tm.first_name, tm.avatar_initials, tm.avatar_color,
              tm.role, tm.department
       FROM selector_scores ss
       JOIN team_members tm ON tm.id = ss.team_member_id
       WHERE ss.venue_id = $1 AND ss.week_ending = $2
       ORDER BY ss.rank_in_venue ASC NULLS LAST`,
      [venueId, week],
    );

    // Venue score
    const venueScore = await db.query<Row>(
      `SELECT vs.*, v.name AS venue_name, v.short_name
       FROM venue_scores vs JOIN venues v ON v.id = vs.venue_id
       WHERE vs.venue_id = $1 AND vs.week_ending = $2`,
      [venueId, week],
    );

    // League
    const league = await db.query<Row>(
      `SELECT vs.total_score, vs.score_change, vs.league_position, v.name AS venue_name, v.short_name
       FROM venue_scores vs JOIN venues v ON v.id = vs.venue_id
       WHERE vs.week_ending = $1 ORDER BY vs.league_position ASC`,
      [week],
    );

    // Focus message
    const focus = await db.query<Row>(
      `SELECT message FROM focus_messages WHERE venue_id = $1 AND week_ending = $2`,
      [venueId, week],
    );

    // Update last accessed
    await db.query(`UPDATE display_tokens SET last_accessed = NOW() WHERE token = $1`, [req.params['token']]);

    ok(res, {
      venue: { id: venueId, name: venueName, shortName: venueShort },
      weekEnding: week,
      themeConfig,
      members: scores.rows,
      venueScore: venueScore.rows[0] ?? null,
      league: league.rows,
      focusMessage: focus.rows[0]?.['message'] ?? null,
    });
  } catch (e) { next(e); }
});

// ----------------------------------------------------------------
// FOCUS MESSAGE (coach sets weekly focus shown on TV)
// ----------------------------------------------------------------
router.post('/focus', auth, async (req, res, next) => {
  try {
    const user = (req as Request & { user: { userId: string } }).user;
    const body = z.object({
      venueId:    z.string().uuid(),
      message:    z.string().min(1).max(280),
      weekEnding: z.string().optional(),
    }).parse(req.body);

    const week = body.weekEnding ?? weekStr();
    await db.query(
      `INSERT INTO focus_messages (id, venue_id, message, set_by_id, week_ending)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (venue_id, week_ending) DO UPDATE SET message = EXCLUDED.message, set_by_id = EXCLUDED.set_by_id`,
      [randomUUID(), body.venueId, body.message, user.userId, week],
    );
    ok(res, { success: true });
  } catch (e) { next(e); }
});

export default router;

// ----------------------------------------------------------------
// DISPLAY TOKENS — CRUD
// ----------------------------------------------------------------
router.get('/display-tokens', auth, async (req, res, next) => {
  try {
    const result = await db.query<Row>(
      `SELECT dt.*, v.name AS venue_name, v.short_name
       FROM display_tokens dt
       JOIN venues v ON v.id = dt.venue_id
       WHERE dt.is_active = true
       ORDER BY v.name`,
    );
    ok(res, result.rows);
  } catch (e) { next(e); }
});

router.post('/display-tokens', auth, async (req, res, next) => {
  try {
    const body = z.object({
      venueId:     z.string().uuid(),
      themeConfig: z.record(z.unknown()).default({}),
    }).parse(req.body);

    const token = randomUUID().replace(/-/g, '');
    const result = await db.query<Row>(
      `INSERT INTO display_tokens (id, venue_id, token, theme_config)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [randomUUID(), body.venueId, token, JSON.stringify(body.themeConfig)],
    );
    ok(res, result.rows[0], 201);
  } catch (e) { next(e); }
});

router.put('/display-tokens/:id', auth, async (req, res, next) => {
  try {
    const body = z.object({ themeConfig: z.record(z.unknown()) }).parse(req.body);
    const result = await db.query<Row>(
      `UPDATE display_tokens SET theme_config = $1 WHERE id = $2 RETURNING *`,
      [JSON.stringify(body.themeConfig), req.params['id']],
    );
    ok(res, result.rows[0]);
  } catch (e) { next(e); }
});

router.delete('/display-tokens/:id', auth, adminOnly, async (req, res, next) => {
  try {
    await db.query(`UPDATE display_tokens SET is_active = false WHERE id = $1`, [req.params['id']]);
    ok(res, { success: true });
  } catch (e) { next(e); }
});

// ----------------------------------------------------------------
// RESDIARY SYNC — trigger manually or via cron
// ----------------------------------------------------------------
router.post('/sync/resdiary', auth, async (req, res, next) => {
  try {
    const user = (req as Request & { user: { role: string } }).user;
    if (user.role !== 'admin') return err(res, 'Admin only', 403);

    const { weekEnding } = z.object({ weekEnding: z.string().optional() }).parse(req.body);
    const week = weekEnding ?? (() => {
      const today = new Date();
      const day = today.getDay();
      const sunday = new Date(today);
      sunday.setDate(today.getDate() - (day === 0 ? 0 : day));
      return sunday.toISOString().split('T')[0]!;
    })();

    // Run async — don't block the response
    const { createResDiaryConnector } = await import('../connectors/resdiary.js');
    const connector = createResDiaryConnector();
    if (!connector) return err(res, 'ResDiary connector not configured — add RESDIARY_PASSWORD to .env', 400);

    void connector.syncAllVenues(week).catch(e => console.error('[ResDiary sync]', e));

    ok(res, { message: `ResDiary sync started for week ending ${week}`, weekEnding: week });
  } catch (e) { next(e); }
});

// ResDiary venue metrics — for display in admin
router.get('/metrics/resdiary', auth, async (req, res, next) => {
  try {
    const week = (req.query['weekEnding'] as string | undefined) ?? (() => {
      const today = new Date();
      const day = today.getDay();
      const s = new Date(today);
      s.setDate(today.getDate() - (day === 0 ? 0 : day));
      return s.toISOString().split('T')[0]!;
    })();

    const result = await db.query(
      `SELECT m.*, v.name AS venue_name, v.short_name
       FROM resdiary_venue_metrics m
       JOIN venues v ON v.id = m.venue_id
       WHERE m.week_ending = $1
       ORDER BY v.name`,
      [week],
    ).catch(() => ({ rows: [] as Record<string, unknown>[] }));

    ok(res, result.rows);
  } catch (e) { next(e); }
});

// ----------------------------------------------------------------
// TRAIL SYNC
// ----------------------------------------------------------------
router.post('/sync/trail', auth, async (req, res, next) => {
  try {
    const user = (req as Request & { user: { role: string } }).user;
    if (user.role !== 'admin') return err(res, 'Admin only', 403);

    const { weekEnding } = z.object({ weekEnding: z.string().optional() }).parse(req.body);
    const week = weekEnding ?? sundayWeekEnding();

    const { createTrailConnector } = await import('../connectors/trail.js');
    const connector = createTrailConnector();
    if (!connector) return err(res, 'Trail connector not configured — add TRAIL_API_KEY to .env', 400);

    void connector.syncAllVenues(week).catch(e => console.error('[Trail sync]', e));
    ok(res, { message: `Trail sync started for week ending ${week}`, weekEnding: week });
  } catch (e) { next(e); }
});

router.post('/sync/trail/test', auth, async (req, res, next) => {
  try {
    const { createTrailConnector } = await import('../connectors/trail.js');
    const connector = createTrailConnector();
    if (!connector) return err(res, 'Trail connector not configured', 400);
    const result = await connector.testConnection();
    ok(res, result);
  } catch (e) { next(e); }
});

router.get('/metrics/trail', auth, async (req, res, next) => {
  try {
    const week = (req.query['weekEnding'] as string | undefined) ?? sundayWeekEnding();
    const result = await db.query(
      `SELECT m.*, v.name AS venue_name
       FROM trail_venue_metrics m
       JOIN venues v ON v.id = m.venue_id
       WHERE m.week_ending = $1
       ORDER BY m.trail_score DESC`,
      [week],
    ).catch(() => ({ rows: [] as Record<string, unknown>[] }));
    ok(res, result.rows);
  } catch (e) { next(e); }
});

function sundayWeekEnding(): string {
  const today = new Date();
  const day = today.getDay();
  const sunday = new Date(today);
  sunday.setDate(today.getDate() - (day === 0 ? 0 : day));
  return sunday.toISOString().split('T')[0]!;
}
