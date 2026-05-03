"use strict";
// ================================================================
// TEST PLAYER — API Routes (Express)
// All routes that power the Test Player front end and TV display.
// ================================================================
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const zod_1 = require("zod");
const crypto_1 = require("crypto");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const database_js_1 = require("../config/database.js");
const env_js_1 = require("../config/env.js");
const selectorRunner_js_1 = require("../services/selectorRunner.js");
const base_js_1 = require("../connectors/base.js");
const registry_js_1 = require("../connectors/registry.js");
const router = (0, express_1.Router)();
// ----------------------------------------------------------------
// HELPERS
// ----------------------------------------------------------------
function ok(res, data, status = 200) {
    res.status(status).json({ data, error: null });
}
function err(res, message, code = 400) {
    res.status(code).json({ data: null, error: { message } });
}
const weekStr = () => {
    const today = new Date();
    const day = today.getDay();
    const sunday = new Date(today);
    sunday.setDate(today.getDate() - (day === 0 ? 0 : day));
    return sunday.toISOString().split('T')[0];
};
// ----------------------------------------------------------------
// AUTH
// ----------------------------------------------------------------
router.post('/auth/login', async (req, res, next) => {
    try {
        const { email, password } = zod_1.z.object({
            email: zod_1.z.string().email(),
            password: zod_1.z.string().min(1),
        }).parse(req.body);
        const result = await database_js_1.db.query(`SELECT id, email, password_hash, first_name, last_name, role, venue_id, is_active
       FROM platform_users WHERE email = $1`, [email.toLowerCase()]);
        const user = result.rows[0];
        const hash = user?.['password_hash'] ?? '$2a$12$invalid';
        const valid = await bcryptjs_1.default.compare(password, hash);
        if (!user || !user['is_active'] || !valid) {
            return err(res, 'Invalid email or password', 401);
        }
        await database_js_1.db.query(`UPDATE platform_users SET last_login = NOW() WHERE id = $1`, [user['id']]);
        const token = jsonwebtoken_1.default.sign({ userId: user['id'], email: user['email'], role: user['role'], venueId: user['venue_id'] }, env_js_1.env.JWT_SECRET, { expiresIn: '7d' });
        return ok(res, {
            token,
            user: { id: user['id'], email: user['email'], firstName: user['first_name'],
                lastName: user['last_name'], role: user['role'], venueId: user['venue_id'] },
        });
    }
    catch (e) {
        next(e);
    }
});
// Auth middleware
function auth(req, res, next) {
    if (req.apiKey) return next();
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer '))
        return err(res, 'Unauthorized', 401);
    try {
        const payload = jsonwebtoken_1.default.verify(header.slice(7), env_js_1.env.JWT_SECRET);
        req.user = payload;
        next();
    }
    catch {
        return err(res, 'Invalid token', 401);
    }
}
function adminOnly(req, res, next) {
    const user = req.user;
    if (!user || user.role !== 'admin')
        return err(res, 'Admin access required', 403);
    next();
}

function generateApiKey() {
    const crypto = require('crypto');
    return 'cw_' + crypto.randomBytes(24).toString('base64url').slice(0, 32);
}

async function apiKeyAuth(req, res, next) {
    const headerKey = req.headers['x-api-key'];
    if (!headerKey) return next();
    if (typeof headerKey !== 'string' || !headerKey.startsWith('cw_')) {
        return err(res, 'Invalid API key format', 401);
    }
    const prefix = headerKey.slice(0, 8);
    try {
        const r = await database_js_1.db.query(
            "SELECT id, name, key_hash, rate_limit FROM api_keys WHERE key_prefix=$1 AND revoked_at IS NULL LIMIT 1",
            [prefix]
        );
        if (!r.rows.length) return err(res, 'Invalid API key', 401);
        const row = r.rows[0];
        const okMatch = await bcryptjs_1.default.compare(headerKey, row.key_hash);
        if (!okMatch) return err(res, 'Invalid API key', 401);
        if (req.method !== 'GET') {
            return err(res, 'API keys are read-only', 405);
        }
        const hourBucket = new Date();
        hourBucket.setMinutes(0, 0, 0);
        const usageR = await database_js_1.db.query(
            "INSERT INTO api_key_usage (api_key_id, hour_bucket, request_count) VALUES ($1, $2, 1) " +
            "ON CONFLICT (api_key_id, hour_bucket) DO UPDATE SET request_count = api_key_usage.request_count + 1 " +
            "RETURNING request_count",
            [row.id, hourBucket]
        );
        const used = usageR.rows[0]?.request_count || 0;
        if (used > row.rate_limit) {
            return err(res, 'Rate limit exceeded (' + row.rate_limit + '/hour)', 429);
        }
        database_js_1.db.query("UPDATE api_keys SET last_used_at=NOW() WHERE id=$1", [row.id]).catch(()=>{});
        req.apiKey = { id: row.id, name: row.name };
        req.user = { role: 'api', name: row.name };
        next();
    } catch(e) {
        console.error('[apiKeyAuth]', e.message);
        return err(res, 'API key auth error', 500);
    }
}

router.use(apiKeyAuth);
// ── API KEY ADMIN ──────────────────────────────────────────────────────────
router.get('/admin/api-keys', auth, adminOnly, async (req, res, next) => {
    try {
        const r = await database_js_1.db.query(
            "SELECT id, name, key_prefix, rate_limit, created_at, last_used_at, revoked_at, " +
            "(SELECT COALESCE(SUM(request_count),0) FROM api_key_usage u WHERE u.api_key_id=k.id AND u.hour_bucket >= NOW() - INTERVAL '24 hours') as requests_24h " +
            "FROM api_keys k ORDER BY created_at DESC"
        );
        ok(res, r.rows);
    } catch(e) { next(e); }
});

router.post('/admin/api-keys', auth, adminOnly, async (req, res, next) => {
    try {
        const { name, rate_limit } = req.body || {};
        if (!name || name.length < 2) return err(res, 'Name required', 400);
        const rawKey = generateApiKey();
        const prefix = rawKey.slice(0, 8);
        const hash = await bcryptjs_1.default.hash(rawKey, 10);
        const r = await database_js_1.db.query(
            "INSERT INTO api_keys (name, key_prefix, key_hash, rate_limit, created_by) " +
            "VALUES ($1, $2, $3, $4, $5) RETURNING id, name, key_prefix, rate_limit, created_at",
            [name, prefix, hash, rate_limit || 1000, req.user.sub || null]
        );
        ok(res, Object.assign({}, r.rows[0], { key: rawKey, warning: 'Copy this key now. It will not be shown again.' }));
    } catch(e) { next(e); }
});

router.delete('/admin/api-keys/:id', auth, adminOnly, async (req, res, next) => {
    try {
        const r = await database_js_1.db.query(
            "UPDATE api_keys SET revoked_at=NOW() WHERE id=$1 AND revoked_at IS NULL RETURNING id, name",
            [req.params.id]
        );
        if (!r.rows.length) return err(res, 'Key not found or already revoked', 404);
        ok(res, { revoked: r.rows[0] });
    } catch(e) { next(e); }
});

// ── CLUB HEALTH ────────────────────────────────────────────────────────────
let _clubHealthCache = { at: 0, data: null };
const CLUB_HEALTH_CACHE_MS = 30000;

router.get('/club/health', auth, async (req, res, next) => {
  try {
    const now = Date.now();
    if (_clubHealthCache.data && (now - _clubHealthCache.at) < CLUB_HEALTH_CACHE_MS) {
      return ok(res, _clubHealthCache.data);
    }

    const checks = [];
    const since = (ts) => {
      if (!ts) return null;
      return Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000); // seconds
    };
    const fmtAge = (sec) => {
      if (sec === null) return '—';
      if (sec < 60) return Math.round(sec) + 's';
      if (sec < 3600) return Math.round(sec/60) + ' min';
      if (sec < 86400) return (sec/3600).toFixed(1) + 'h';
      return (sec/86400).toFixed(1) + ' days';
    };

    // 1. Relay
    try {
      const r = await database_js_1.db.query("SELECT MAX(datetime_opened) AS last_tx, COUNT(*) FILTER (WHERE datetime_opened > NOW() - INTERVAL '24 hours') AS tx_24h FROM relay_transactions");
      const last = r.rows[0].last_tx;
      const ageS = since(last);
      let status = 'green', message = 'Last transaction ' + fmtAge(ageS) + ' ago';
      if (!last) { status = 'red'; message = 'No transactions ever received'; }
      else if (ageS > 21600) { status = 'red'; message = 'No transactions for ' + fmtAge(ageS); }
      else if (ageS > 3600) { status = 'amber'; message = 'No transactions for ' + fmtAge(ageS); }
      checks.push({ id: 'relay_freshness', source: 'Relay', status, message, details: { last_event_at: last, transactions_24h: Number(r.rows[0].tx_24h) } });
    } catch(e) {
      checks.push({ id: 'relay_freshness', source: 'Relay', status: 'red', message: 'Query failed: ' + e.message });
    }

    // 2. ResDiary webhooks
    try {
      const r = await database_js_1.db.query("SELECT MAX(received_at) AS last_event, COUNT(*) FILTER (WHERE received_at > NOW() - INTERVAL '24 hours') AS evts_24h FROM resdiary_webhook_events");
      const last = r.rows[0].last_event;
      const ageS = since(last);
      let status = 'green', message = 'Last event ' + fmtAge(ageS) + ' ago';
      if (!last) { status = 'red'; message = 'No webhook events ever'; }
      else if (ageS > 43200) { status = 'red'; message = 'No webhook events for ' + fmtAge(ageS); }
      else if (ageS > 14400) { status = 'amber'; message = 'Quiet for ' + fmtAge(ageS); }
      checks.push({ id: 'resdiary_webhook', source: 'ResDiary', status, message, details: { last_event_at: last, events_24h: Number(r.rows[0].evts_24h) } });
    } catch(e) {
      checks.push({ id: 'resdiary_webhook', source: 'ResDiary', status: 'red', message: 'Query failed: ' + e.message });
    }

    // 3. ResDiary API auth (we know it's broken — flag explicitly)
    checks.push({ id: 'resdiary_api', source: 'ResDiary', status: 'amber', message: 'Data Extraction API: password reset pending', details: { issue: '401 from /api/Jwt/Token — awaiting password reset from ResDiary support' } });

    // 4. Rotaready
    try {
      const r = await database_js_1.db.query("SELECT MAX(pay_date) AS last_pay, NOW()::date - MAX(pay_date) AS days_behind, COUNT(*) FILTER (WHERE hours_paid > 0) AS nonzero, COUNT(*) AS total FROM rotaready_pay");
      const row = r.rows[0];
      let status = 'green', message = 'Last pay date ' + (row.days_behind || 0) + 'd behind';
      if (!row.last_pay) { status = 'red'; message = 'No Rotaready data'; }
      else if (Number(row.days_behind) > 3) { status = 'red'; message = (row.days_behind) + ' days behind'; }
      else if (Number(row.days_behind) > 1 || Number(row.nonzero) === 0) {
        status = 'amber';
        if (Number(row.nonzero) === 0) message = 'hours_paid all zero (using estimated hours)';
        else message = (row.days_behind) + ' days behind';
      }
      checks.push({ id: 'rotaready_freshness', source: 'Rotaready', status, message, details: { last_pay_date: row.last_pay, days_behind: Number(row.days_behind), rows_with_hours: Number(row.nonzero), total_rows: Number(row.total) } });
    } catch(e) {
      checks.push({ id: 'rotaready_freshness', source: 'Rotaready', status: 'red', message: 'Query failed: ' + e.message });
    }

    // 5. Trail
    try {
      const r = await database_js_1.db.query("SELECT MAX(synced_at) AS last_sync FROM trail_venue_metrics");
      const last = r.rows[0].last_sync;
      const ageS = since(last);
      let status = 'green', message = 'Last sync ' + fmtAge(ageS) + ' ago';
      if (!last) { status = 'red'; message = 'No Trail data'; }
      else if (ageS > 108000) { status = 'red'; message = 'Last sync ' + fmtAge(ageS) + ' ago'; }
      else if (ageS > 21600) { status = 'amber'; message = 'Last sync ' + fmtAge(ageS) + ' ago'; }
      checks.push({ id: 'trail_freshness', source: 'Trail', status, message, details: { last_sync: last } });
    } catch(e) {
      checks.push({ id: 'trail_freshness', source: 'Trail', status: 'red', message: 'Query failed: ' + e.message });
    }

    // 6. Selector recalc (use created_at)
    try {
      const r = await database_js_1.db.query("SELECT MAX(created_at) AS last_run FROM selector_scores");
      const last = r.rows[0].last_run;
      const ageS = since(last);
      let status = 'green', message = 'Last recalc ' + fmtAge(ageS) + ' ago';
      if (!last) { status = 'amber'; message = 'No scores recorded'; }
      else if (ageS > 604800) { status = 'red'; message = 'Last recalc ' + fmtAge(ageS) + ' ago'; }
      else if (ageS > 172800) { status = 'amber'; message = 'Last recalc ' + fmtAge(ageS) + ' ago'; }
      checks.push({ id: 'selector_recalc', source: 'Selector', status, message, details: { last_run: last } });
    } catch(e) {
      checks.push({ id: 'selector_recalc', source: 'Selector', status: 'amber', message: 'Cannot determine recalc time' });
    }

    // 7. Disk
    try {
      const { execSync } = require('child_process');
      const out = execSync("df / --output=pcent | tail -1").toString().trim();
      const usedPct = parseInt(out.replace('%',''));
      const freePct = 100 - usedPct;
      let status = 'green', message = freePct + '% free';
      if (freePct < 10) { status = 'red'; }
      else if (freePct < 25) { status = 'amber'; }
      checks.push({ id: 'disk_space', source: 'System', status, message, details: { used_pct: usedPct, free_pct: freePct } });
    } catch(e) {
      checks.push({ id: 'disk_space', source: 'System', status: 'amber', message: 'Could not check disk' });
    }

    // 8. Postgres connections
    try {
      const r = await database_js_1.db.query("SELECT count(*) FROM pg_stat_activity WHERE state='active'");
      const conn = Number(r.rows[0].count);
      let status = 'green', message = conn + ' active connections';
      if (conn > 90) status = 'red';
      else if (conn > 50) status = 'amber';
      checks.push({ id: 'pg_connections', source: 'Postgres', status, message, details: { active: conn } });
    } catch(e) {
      checks.push({ id: 'pg_connections', source: 'Postgres', status: 'amber', message: 'Cannot count connections' });
    }

    // Summary
    const summary = {
      green: checks.filter(c => c.status === 'green').length,
      amber: checks.filter(c => c.status === 'amber').length,
      red: checks.filter(c => c.status === 'red').length,
      total: checks.length,
      worst: checks.some(c => c.status === 'red') ? 'red' : checks.some(c => c.status === 'amber') ? 'amber' : 'green'
    };

    const payload = { checks, summary, generated_at: new Date().toISOString() };
    _clubHealthCache = { at: Date.now(), data: payload };
    ok(res, payload);
  } catch(e) { next(e); }
});

// ── HARRY / OUTBOUND READ ENDPOINTS ─────────────────────────────────────────

// ResDiary raw webhook events (NoShow, Cancelled, MealStatusChanged, etc.)
router.get('/resdiary/events', auth, async (req, res, next) => {
  try {
    const { bookingId, eventType, from, to, limit, offset } = req.query;
    const conditions = [];
    const params = [];
    if (bookingId) { params.push(bookingId); conditions.push("(payload->>'BookingId')::text=$"+params.length); }
    if (eventType) { params.push(eventType); conditions.push('event_type=$'+params.length); }
    if (from) { params.push(from); conditions.push('received_at>=$'+params.length); }
    if (to) { params.push(to); conditions.push('received_at<=$'+params.length); }
    const where = conditions.length ? 'WHERE '+conditions.join(' AND ') : '';
    const lim = Math.min(parseInt(limit) || 500, 5000);
    const off = parseInt(offset) || 0;
    params.push(lim); const limIdx = params.length;
    params.push(off); const offIdx = params.length;
    const cR = await database_js_1.db.query('SELECT COUNT(*) AS total FROM resdiary_webhook_events ' + where, params.slice(0, params.length - 2));
    const r = await database_js_1.db.query(
      'SELECT id, event_type, restaurant_name, payload, processed, received_at ' +
      'FROM resdiary_webhook_events ' + where + ' ORDER BY received_at DESC LIMIT $' + limIdx + ' OFFSET $' + offIdx,
      params
    );
    ok(res, { rows: r.rows, total: Number(cR.rows[0].total), limit: lim, offset: off });
  } catch(e) { next(e); }
});

// Rotaready pay/shift rows (one row per person per day)
router.get('/rotaready/pay', auth, async (req, res, next) => {
  try {
    const { userId, from, to, locationId, limit, offset } = req.query;
    const conditions = [];
    const params = [];
    if (userId) { params.push(userId); conditions.push('rp.user_id=$'+params.length); }
    if (from) { params.push(from); conditions.push('rp.pay_date>=$'+params.length); }
    if (to) { params.push(to); conditions.push('rp.pay_date<=$'+params.length); }
    if (locationId) { params.push(locationId); conditions.push('rp.location_id=$'+params.length); }
    const where = conditions.length ? 'WHERE '+conditions.join(' AND ') : '';
    const lim = Math.min(parseInt(limit) || 500, 5000);
    const off = parseInt(offset) || 0;
    params.push(lim); const limIdx = params.length;
    params.push(off); const offIdx = params.length;
    const cR = await database_js_1.db.query('SELECT COUNT(*) AS total FROM rotaready_pay rp ' + where, params.slice(0, params.length - 2));
    const r = await database_js_1.db.query(
      "SELECT rp.user_id, rp.entity_id, rp.location_id, rp.pay_date, rp.basic_pay, rp.total_pay, rp.hours_paid, rp.hourly_rate, rp.is_salaried, rp.synced_at, " +
      "tm.display_name, tm.role, tm.department, " +
      "CASE WHEN rp.hourly_rate > 5 AND NOT rp.is_salaried THEN ROUND((rp.basic_pay / rp.hourly_rate)::numeric, 2) " +
      "WHEN rp.is_salaried AND rp.total_pay > 0 THEN ROUND((rp.total_pay / 12.21)::numeric, 2) " +
      "ELSE 0 END AS estimated_hours " +
      "FROM rotaready_pay rp LEFT JOIN team_members tm ON tm.rota_id = rp.user_id::text " +
      where + ' ORDER BY rp.pay_date DESC, rp.user_id ASC LIMIT $' + limIdx + ' OFFSET $' + offIdx,
      params
    );
    ok(res, { rows: r.rows, total: Number(cR.rows[0].total), limit: lim, offset: off });
  } catch(e) { next(e); }
});

// Rotaready users (staff with rota mapping)
router.get('/rotaready/users', auth, async (req, res, next) => {
  try {
    const { locationId, limit, offset } = req.query;
    const conditions = ['tm.rota_id IS NOT NULL'];
    const params = [];
    if (locationId) { params.push(locationId); conditions.push('EXISTS (SELECT 1 FROM rotaready_pay rp WHERE rp.user_id::text = tm.rota_id AND rp.location_id=$'+params.length+')'); }
    const where = 'WHERE '+conditions.join(' AND ');
    const lim = Math.min(parseInt(limit) || 500, 5000);
    const off = parseInt(offset) || 0;
    params.push(lim); const limIdx = params.length;
    params.push(off); const offIdx = params.length;
    const r = await database_js_1.db.query(
      "SELECT tm.id AS team_member_id, tm.rota_id::integer AS rotaready_user_id, tm.display_name, tm.role, tm.department, tm.venue_id, v.name AS venue, " +
      "(SELECT MAX(pay_date) FROM rotaready_pay WHERE user_id::text = tm.rota_id) AS last_pay_date, " +
      "(SELECT MAX(hourly_rate) FROM rotaready_pay WHERE user_id::text = tm.rota_id) AS hourly_rate, " +
      "(SELECT BOOL_OR(is_salaried) FROM rotaready_pay WHERE user_id::text = tm.rota_id) AS is_salaried " +
      "FROM team_members tm LEFT JOIN venues v ON v.id = tm.venue_id " +
      where + ' ORDER BY tm.display_name LIMIT $' + limIdx + ' OFFSET $' + offIdx,
      params
    );
    ok(res, { rows: r.rows, limit: lim, offset: off });
  } catch(e) { next(e); }
});

// API self-documentation - lists all read endpoints
router.get('/docs', auth, async (req, res, next) => {
  ok(res, {
    base_url: 'https://theclub.thecatandwickets.com/api/v1',
    auth: { type: 'header', name: 'X-API-Key', example: 'X-API-Key: cw_xxxxx...' },
    rate_limit: '1000 requests per hour per key',
    method_restriction: 'API keys are GET-only. POST/PUT/DELETE return 405.',
    endpoints: [
      { path: '/scores/leaderboard', method: 'GET', description: 'Team selector scores ranked', params: ['period (week|last_week|month|today)', 'venue (griffin|taprun|longhop)'] },
      { path: '/scores/:teamMemberId', method: 'GET', description: 'Detailed score history for one team member', params: [] },
      { path: '/squad', method: 'GET', description: 'Active team members across all venues', params: [] },
      { path: '/league', method: 'GET', description: 'Venue-level league table', params: [] },
      { path: '/clerks', method: 'GET', description: 'POS clerks with team_member mapping', params: [] },
      { path: '/venues', method: 'GET', description: 'Venue list', params: [] },
      { path: '/bookings/resdiary', method: 'GET', description: 'ResDiary bookings (full data)', params: ['venue', 'date', 'from', 'to', 'status', 'limit', 'offset'] },
      { path: '/bookings/resdiary/today', method: 'GET', description: 'Today summary per venue', params: [] },
      { path: '/resdiary/events', method: 'GET', description: 'Raw ResDiary webhook events', params: ['bookingId', 'eventType', 'from', 'to', 'limit', 'offset'] },
      { path: '/rotaready/pay', method: 'GET', description: 'Rotaready pay/shift rows (one per person per day)', params: ['userId', 'from', 'to', 'locationId', 'limit', 'offset'] },
      { path: '/rotaready/users', method: 'GET', description: 'Staff with Rotaready mapping + roles + rates', params: ['locationId', 'limit', 'offset'] },
      { path: '/metrics/asph', method: 'GET', description: 'Average spend per head, per venue', params: [] },
      { path: '/metrics/google/ratings', method: 'GET', description: 'Google review summary', params: [] },
      { path: '/metrics/google/reviews', method: 'GET', description: 'Latest Google reviews', params: [] },
      { path: '/metrics/trail/breakdown', method: 'GET', description: 'Trail compliance scores by venue', params: ['weekEnding'] },
      { path: '/metrics/resdiary', method: 'GET', description: 'ResDiary daily metrics summary', params: ['startDate', 'endDate'] },
      { path: '/metrics/team/flex', method: 'GET', description: 'Team flexibility metrics', params: [] },
      { path: '/products/leaderboard', method: 'GET', description: 'Top selling products', params: ['period', 'venue', 'salesGroup'] },
      { path: '/products/clerks', method: 'GET', description: 'Which clerks sold a given product', params: ['product', 'period', 'venue'] },
      { path: '/transactions/recent', method: 'GET', description: 'Recent POS transactions', params: ['limit'] },
      { path: '/transactions/summary', method: 'GET', description: 'Transaction count summary', params: [] },
      { path: '/selector/metrics', method: 'GET', description: 'Active selector metric configurations', params: [] }
    ]
  });
});

// ----------------------------------------------------------------
// VENUES
// ----------------------------------------------------------------
router.get('/venues', auth, async (req, res, next) => {
    try {
        const result = await database_js_1.db.query(`SELECT v.*, COUNT(tm.id) AS member_count
       FROM venues v
       LEFT JOIN team_members tm ON tm.venue_id = v.id AND tm.is_active = true
       WHERE v.is_active = true
       GROUP BY v.id ORDER BY v.name`);
        ok(res, result.rows);
    }
    catch (e) {
        next(e);
    }
});
// ----------------------------------------------------------------
// SQUAD (team members)
// ----------------------------------------------------------------
router.get('/squad', auth, async (req, res, next) => {
    try {
        const user = req.user;
        // Support both venueId (UUID) and venue/locationId (location code)
        const locMap = {'griffin':'0001','taprun':'0002','longhop':'0003'};
        const locationId = req.query['locationId'] || locMap[req.query['venue']] || null;
        const venueUuidMap = {'0001':'e87b5986-0826-4464-ad62-e55175f9c3c4','0002':'38749619-c192-45d1-806b-2fdc5922adea','0003':'d9657ea0-19c4-4793-9c0c-21fd4179ac56'};
        const venueId = req.query['venueId'] ?? (locationId ? venueUuidMap[locationId] : null) ?? user.venueId ?? null;
        
        const result = await database_js_1.db.query(
          "SELECT tm.*, v.name AS venue_name, v.short_name AS venue_short_name, " +
          "cvm.location_id, " +
          "ss.total_score, ss.tier, ss.programme_status, ss.score_change, " +
          "ss.assessment_score, ss.epos_score, ss.operational_score, " +
          "ss.coaching_narrative, ss.rank_in_venue, " +
          "cu.employee_id as cpl_employee_id, " +
          "(SELECT COUNT(*) FROM cpl_training ct WHERE ct.employee_id=cu.employee_id AND ct.status='Complete') as cpl_completed, " +
          "(SELECT COUNT(*) FROM cpl_training ct WHERE ct.employee_id=cu.employee_id) as cpl_total, " +
          "(SELECT ROUND(AVG(ct.score)::numeric,0) FROM cpl_training ct WHERE ct.employee_id=cu.employee_id AND ct.status='Complete') as cpl_avg_score, " +
          "(SELECT ct.status FROM cpl_training ct WHERE ct.employee_id=cu.employee_id AND ct.course_name LIKE '%Food Safety%' LIMIT 1) as food_safety_status, " +
          "(SELECT ct.status FROM cpl_training ct WHERE ct.employee_id=cu.employee_id AND ct.course_name LIKE '%Allergen%' LIMIT 1) as allergen_status, " +
          "(SELECT ct.status FROM cpl_training ct WHERE ct.employee_id=cu.employee_id AND ct.course_name LIKE '%Batting Order%' LIMIT 1) as induction_status, " +
          "(SELECT ct.status FROM cpl_training ct WHERE ct.employee_id=cu.employee_id AND ct.course_name LIKE '%Induction%' LIMIT 1) as cw_induction_status " +
          "FROM team_members tm " +
          "JOIN venues v ON v.id=tm.venue_id " +
          "LEFT JOIN connector_venue_mappings cvm ON cvm.venue_id=tm.venue_id AND cvm.connector='relay' " +
          "LEFT JOIN selector_scores ss ON ss.team_member_id=tm.id AND ss.week_ending=$2 " +
          "LEFT JOIN cpl_users cu ON LOWER(cu.first_name)=LOWER(tm.first_name) AND LOWER(cu.last_name)=LOWER(tm.last_name) AND cu.active=true " +
          "WHERE tm.is_active=true AND ($1::uuid IS NULL OR tm.venue_id=$1) " +
          "ORDER BY tm.selector_score DESC NULLS LAST, tm.first_name",
          [venueId, weekStr()]
        );
        ok(res, result.rows);
    }
    catch (e) {
        next(e);
    }
});
router.post('/squad', auth, adminOnly, async (req, res, next) => {
    try {
        const body = zod_1.z.object({
            venueId: zod_1.z.string().uuid(),
            firstName: zod_1.z.string().min(1),
            lastName: zod_1.z.string().min(1),
            role: zod_1.z.string().optional(),
            department: zod_1.z.enum(['Kitchen', 'FOH', 'Bar', 'Management']).optional(),
            avatarColor: zod_1.z.string().regex(/^#[0-9a-fA-F]{6}$/).default('#fd6f53'),
            eposId: zod_1.z.string().optional(),
            rotaId: zod_1.z.string().optional(),
            joinedAt: zod_1.z.string().optional(),
        }).parse(req.body);
        const initials = (body.firstName[0] + body.lastName[0]).toUpperCase();
        const result = await database_js_1.db.query(`INSERT INTO team_members
         (id, venue_id, first_name, last_name, display_name, role, department,
          avatar_initials, avatar_color, epos_id, rota_id, joined_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING *`, [(0, crypto_1.randomUUID)(), body.venueId, body.firstName, body.lastName,
            `${body.firstName} ${body.lastName}`, body.role ?? null,
            body.department ?? null, initials, body.avatarColor,
            body.eposId ?? null, body.rotaId ?? null, body.joinedAt ?? null]);
        ok(res, result.rows[0], 201);
    }
    catch (e) {
        next(e);
    }
});
// ----------------------------------------------------------------
// MANAGER ASSESSMENT
// ----------------------------------------------------------------
router.get('/assessments', auth, async (req, res, next) => {
    try {
        const venueId = req.query['venueId'];
        const week = req.query['weekEnding'] ?? weekStr();
        const result = await database_js_1.db.query(`SELECT ma.*, tm.display_name, tm.avatar_initials, tm.avatar_color,
              tm.role, tm.department, v.name AS venue_name
       FROM manager_assessments ma
       JOIN team_members tm ON tm.id = ma.team_member_id
       JOIN venues v ON v.id = ma.venue_id
       WHERE ma.week_ending = $1
         AND ($2::uuid IS NULL OR ma.venue_id = $2)
       ORDER BY tm.display_name`, [week, venueId ?? null]);
        ok(res, result.rows);
    }
    catch (e) {
        next(e);
    }
});
// GET assessment form for a member — returns existing or empty
router.get('/assessments/:memberId', auth, async (req, res, next) => {
    try {
        const week = req.query['weekEnding'] ?? weekStr();
        const result = await database_js_1.db.query(`SELECT * FROM manager_assessments WHERE team_member_id = $1 AND week_ending = $2`, [req.params['memberId'], week]);
        ok(res, result.rows[0] ?? null);
    }
    catch (e) {
        next(e);
    }
});
// POST / upsert assessment — triggers selector re-run for this member
router.post('/assessments', auth, async (req, res, next) => {
    try {
        const user = req.user;
        const body = zod_1.z.object({
            teamMemberId: zod_1.z.string().uuid(),
            venueId: zod_1.z.string().uuid(),
            weekEnding: zod_1.z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
            productConfidence: zod_1.z.number().min(1).max(5),
            guestWarmth: zod_1.z.number().min(1).max(5),
            tableReading: zod_1.z.number().min(1).max(5),
            valuesAlignment: zod_1.z.number().min(1).max(5),
            coachingTier: zod_1.z.enum(['could-say', 'should-say', 'have-to']),
            coachingNote: zod_1.z.string().optional(),
            dontSayFlags: zod_1.z.array(zod_1.z.string()).optional(),
        }).parse(req.body);
        // Weighted assessment score (product confidence and warmth weighted higher)
        const assessmentScore = (body.productConfidence * 1.3 +
            body.guestWarmth * 1.3 +
            body.tableReading * 1.0 +
            body.valuesAlignment * 1.4) / (1.3 + 1.3 + 1.0 + 1.4) / 5 * 100;
        const result = await database_js_1.db.query(`INSERT INTO manager_assessments
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
       RETURNING *`, [(0, crypto_1.randomUUID)(), body.teamMemberId, body.venueId, user.userId, body.weekEnding,
            body.productConfidence, body.guestWarmth, body.tableReading, body.valuesAlignment,
            body.coachingTier, body.coachingNote ?? null,
            body.dontSayFlags ?? null, Math.round(assessmentScore * 100) / 100]);
        ok(res, result.rows[0], 201);
    }
    catch (e) {
        next(e);
    }
});
// ----------------------------------------------------------------
// SCORES & LEAGUE
// ----------------------------------------------------------------
router.get('/scores', auth, async (req, res, next) => {
    try {
        const week = req.query['weekEnding'] ?? weekStr();
        const venueId = req.query['venueId'];
        const result = await database_js_1.db.query(`SELECT ss.*, tm.display_name, tm.first_name, tm.avatar_initials, tm.avatar_color,
              tm.role, tm.department, v.name AS venue_name, v.short_name
       FROM selector_scores ss
       JOIN team_members tm ON tm.id = ss.team_member_id
       JOIN venues v ON v.id = ss.venue_id
       WHERE ss.week_ending = $1
         AND ($2::uuid IS NULL OR ss.venue_id = $2)
       ORDER BY ss.rank_in_venue ASC NULLS LAST`, [week, venueId ?? null]);
        ok(res, result.rows);
    }
    catch (e) {
        next(e);
    }
});
router.get('/league', auth, async (req, res, next) => {
    try {
        const week = req.query['weekEnding'] ?? weekStr();
        const result = await database_js_1.db.query(`SELECT vs.*, v.name AS venue_name, v.short_name
       FROM venue_scores vs
       JOIN venues v ON v.id = vs.venue_id
       WHERE vs.week_ending = $1
       ORDER BY vs.league_position ASC`, [week]);
        ok(res, result.rows);
    }
    catch (e) {
        next(e);
    }
});
// ----------------------------------------------------------------
// THE SELECTOR — run on demand
// ----------------------------------------------------------------
router.post('/selector/run', auth, adminOnly, async (req, res, next) => {
    try {
        const { weekEnding } = zod_1.z.object({ weekEnding: zod_1.z.string().optional() }).parse(req.body);
        const result = await (0, selectorRunner_js_1.runSelectorForWeek)(weekEnding);
        ok(res, result);
    }
    catch (e) {
        next(e);
    }
});
// ----------------------------------------------------------------
// CONNECTORS
// ----------------------------------------------------------------
router.get('/connectors', auth, adminOnly, async (req, res, next) => {
    try {
        const result = await database_js_1.db.query(`SELECT id, name, provider, base_url, auth_type, auth_config, is_active,
              last_sync_at, last_sync_status, last_sync_message,
              (credentials_encrypted IS NOT NULL) AS has_credentials,
              created_at
       FROM connectors ORDER BY name`);
        ok(res, result.rows);
    }
    catch (e) {
        next(e);
    }
});
router.post('/connectors', auth, adminOnly, async (req, res, next) => {
    try {
        const body = zod_1.z.object({
            name: zod_1.z.string().min(1),
            provider: zod_1.z.string().min(1),
            baseUrl: zod_1.z.string().url(),
            authType: zod_1.z.enum(['api_key', 'bearer', 'basic']),
            authConfig: zod_1.z.record(zod_1.z.unknown()).default({}),
        }).parse(req.body);
        const result = await database_js_1.db.query(`INSERT INTO connectors (id, name, provider, base_url, auth_type, auth_config)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, name, provider, is_active, created_at`, [(0, crypto_1.randomUUID)(), body.name, body.provider, body.baseUrl, body.authType, JSON.stringify(body.authConfig)]);
        ok(res, result.rows[0], 201);
    }
    catch (e) {
        next(e);
    }
});
router.post('/connectors/:id/credentials', auth, adminOnly, async (req, res, next) => {
    try {
        const creds = zod_1.z.record(zod_1.z.string()).parse(req.body);
        const encrypted = (0, base_js_1.encryptCredentials)(creds);
        await database_js_1.db.query(`UPDATE connectors SET credentials_encrypted = $1 WHERE id = $2`, [encrypted, req.params['id']]);
        ok(res, { success: true, message: 'Credentials stored securely' });
    }
    catch (e) {
        next(e);
    }
});
router.post('/connectors/:id/test', auth, adminOnly, async (req, res, next) => {
    try {
        const connResult = await database_js_1.db.query(`SELECT * FROM connectors WHERE id = $1`, [req.params['id']]);
        const conn = connResult.rows[0];
        if (!conn)
            return err(res, 'Connector not found', 404);
        const credentials = conn['credentials_encrypted']
            ? (0, base_js_1.decryptCredentials)(conn['credentials_encrypted'])
            : {};
        const connector = (0, registry_js_1.getConnector)({
            id: conn['id'],
            provider: conn['provider'],
            baseUrl: conn['base_url'],
            authType: conn['auth_type'],
            authConfig: conn['auth_config'],
            credentials,
        });
        const start = Date.now();
        const result = await connector.testConnection();
        await database_js_1.db.query(`UPDATE connectors SET last_sync_status = $1, last_sync_message = $2, last_sync_at = NOW() WHERE id = $3`, [result.success ? 'success' : 'failed', result.message, conn['id']]);
        ok(res, result);
    }
    catch (e) {
        next(e);
    }
});
// ----------------------------------------------------------------
// TV DISPLAY — public endpoint, token authenticated
// ----------------------------------------------------------------
router.get('/display/:token', async (req, res, next) => {
    try {
        const tokenResult = await database_js_1.db.query(`SELECT dt.*, v.id AS venue_id, v.name AS venue_name, v.short_name
       FROM display_tokens dt
       JOIN venues v ON v.id = dt.venue_id
       WHERE dt.token = $1 AND dt.is_active = true`, [req.params['token']]);
        if (!tokenResult.rows[0])
            return err(res, 'Invalid display token', 401);
        const { venue_id: venueId, venue_name: venueName, short_name: venueShort, theme_config: themeConfig } = tokenResult.rows[0];
        const week = weekStr();
        // Squad scores
        const scores = await database_js_1.db.query(`SELECT ss.total_score, ss.tier, ss.programme_status, ss.score_change,
              ss.rank_in_venue, ss.coaching_narrative,
              tm.display_name, tm.first_name, tm.avatar_initials, tm.avatar_color,
              tm.role, tm.department
       FROM selector_scores ss
       JOIN team_members tm ON tm.id = ss.team_member_id
       WHERE ss.venue_id = $1 AND ss.week_ending = $2
       ORDER BY ss.rank_in_venue ASC NULLS LAST`, [venueId, week]);
        // Venue score
        const venueScore = await database_js_1.db.query(`SELECT vs.*, v.name AS venue_name, v.short_name
       FROM venue_scores vs JOIN venues v ON v.id = vs.venue_id
       WHERE vs.venue_id = $1 AND vs.week_ending = $2`, [venueId, week]);
        // League
        const league = await database_js_1.db.query(`SELECT vs.total_score, vs.score_change, vs.league_position, v.name AS venue_name, v.short_name
       FROM venue_scores vs JOIN venues v ON v.id = vs.venue_id
       WHERE vs.week_ending = $1 ORDER BY vs.league_position ASC`, [week]);
        // Focus message
        const focus = await database_js_1.db.query(`SELECT message FROM focus_messages WHERE venue_id = $1 AND week_ending = $2`, [venueId, week]);
        // Update last accessed
        await database_js_1.db.query(`UPDATE display_tokens SET last_accessed = NOW() WHERE token = $1`, [req.params['token']]);
        ok(res, {
            venue: { id: venueId, name: venueName, shortName: venueShort },
            weekEnding: week,
            themeConfig,
            members: scores.rows,
            venueScore: venueScore.rows[0] ?? null,
            league: league.rows,
            focusMessage: focus.rows[0]?.['message'] ?? null,
        });
    }
    catch (e) {
        next(e);
    }
});
// ----------------------------------------------------------------
// FOCUS MESSAGE (coach sets weekly focus shown on TV)
// ----------------------------------------------------------------
router.post('/focus', auth, async (req, res, next) => {
    try {
        const user = req.user;
        const body = zod_1.z.object({
            venueId: zod_1.z.string().uuid(),
            message: zod_1.z.string().min(1).max(280),
            weekEnding: zod_1.z.string().optional(),
        }).parse(req.body);
        const week = body.weekEnding ?? weekStr();
        await database_js_1.db.query(`INSERT INTO focus_messages (id, venue_id, message, set_by_id, week_ending)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (venue_id, week_ending) DO UPDATE SET message = EXCLUDED.message, set_by_id = EXCLUDED.set_by_id`, [(0, crypto_1.randomUUID)(), body.venueId, body.message, user.userId, week]);
        ok(res, { success: true });
    }
    catch (e) {
        next(e);
    }
});
exports.default = router;
// ----------------------------------------------------------------
// DISPLAY TOKENS — CRUD
// ----------------------------------------------------------------
router.get('/display-tokens', auth, async (req, res, next) => {
    try {
        const result = await database_js_1.db.query(`SELECT dt.*, v.name AS venue_name, v.short_name
       FROM display_tokens dt
       JOIN venues v ON v.id = dt.venue_id
       WHERE dt.is_active = true
       ORDER BY v.name`);
        ok(res, result.rows);
    }
    catch (e) {
        next(e);
    }
});
router.post('/display-tokens', auth, async (req, res, next) => {
    try {
        const body = zod_1.z.object({
            venueId: zod_1.z.string().uuid(),
            themeConfig: zod_1.z.record(zod_1.z.unknown()).default({}),
        }).parse(req.body);
        const token = (0, crypto_1.randomUUID)().replace(/-/g, '');
        const result = await database_js_1.db.query(`INSERT INTO display_tokens (id, venue_id, token, theme_config)
       VALUES ($1,$2,$3,$4) RETURNING *`, [(0, crypto_1.randomUUID)(), body.venueId, token, JSON.stringify(body.themeConfig)]);
        ok(res, result.rows[0], 201);
    }
    catch (e) {
        next(e);
    }
});
router.put('/display-tokens/:id', auth, async (req, res, next) => {
    try {
        const body = zod_1.z.object({ themeConfig: zod_1.z.record(zod_1.z.unknown()) }).parse(req.body);
        const result = await database_js_1.db.query(`UPDATE display_tokens SET theme_config = $1 WHERE id = $2 RETURNING *`, [JSON.stringify(body.themeConfig), req.params['id']]);
        ok(res, result.rows[0]);
    }
    catch (e) {
        next(e);
    }
});
router.delete('/display-tokens/:id', auth, adminOnly, async (req, res, next) => {
    try {
        await database_js_1.db.query(`UPDATE display_tokens SET is_active = false WHERE id = $1`, [req.params['id']]);
        ok(res, { success: true });
    }
    catch (e) {
        next(e);
    }
});
// RELAY WEBHOOK
router.post('/webhooks/relay', async (req, res, next) => {
    try {
        const apiKey = req.headers['x-api-key'] ?? req.headers['authorization']?.replace('Bearer ', '');
        const expectedKey = process.env['RELAY_API_KEY'];
        if (!expectedKey || apiKey !== expectedKey)
            return err(res, 'Unauthorized', 401);
        const payload = req.body;
        if (!payload?.Id)
            return err(res, 'Invalid payload', 400);
        const rawId = (0, crypto_1.randomUUID)();
        await database_js_1.db.query('INSERT INTO relay_raw_events (id, location_id, payload) VALUES ($1, $2, $3)', [rawId, payload.LocationId ?? null, JSON.stringify(payload)]);
        await database_js_1.db.query(`INSERT INTO relay_transactions (id,access_organisation_id,business_date,change_given,closed_by_clerk_id,company_code,covers,datetime_closed,datetime_opened,location_id,parent_transaction_id,seating_area,source,terminal_id,tips,total_discount,total_gross_item_cost,total_net_item_cost,total_payments,total_service_charge,total_tax,total_to_pay_amount,total_wastage_cost) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23) ON CONFLICT (id) DO NOTHING`, [payload.Id, payload.AccessOrganisationId ?? null, payload.BusinessDate, payload.ChangeGiven ?? 0, payload.ClosedByClerkId ?? null, payload.CompanyCode ?? null, payload.Covers ?? null, payload.DateTimeClosed ?? null, payload.DateTimeOpened, payload.LocationId ?? null, payload.ParentTransactionId ?? null, payload.SeatingArea ?? null, payload.Source ?? null, payload.TerminalId ?? null, payload.Tips ?? 0, payload.TotalDiscount ?? 0, payload.TotalGrossItemCost ?? 0, payload.TotalNetItemCost ?? 0, payload.TotalPayments ?? 0, payload.TotalServiceCharge ?? 0, payload.TotalTax ?? 0, payload.TotalToPayAmount ?? 0, payload.TotalWastageCost ?? 0]);
        for (const item of (payload.SoldItems ?? [])) {
            await database_js_1.db.query(`INSERT INTO relay_sold_items (transaction_id,item_id,added_by_clerk_id,datetime_sold,name,quantity,sales_group,individual_gross_price,individual_net_price,total_net_price,total_gross_price,total_discount,total_service_charge,total_tax,is_refunded) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, [payload.Id, item.Id ?? null, item.AddedByClerkId ?? null, item.DateTimeSold ?? null, item.Name ?? null, item.Quantity ?? 1, item.SalesGroup ?? null, item.IndividualGrossPrice ?? 0, item.IndividualNetPrice ?? 0, item.TotalNetPrice ?? 0, item.TotalGrossPrice ?? 0, item.TotalDiscount ?? 0, item.TotalServiceCharge ?? 0, item.TotalTax ?? 0, item.IsRefunded ?? false]);
            if (item.AddedByClerkId)
                await database_js_1.db.query(`INSERT INTO relay_clerk_mappings (clerk_id,location_id) VALUES ($1,$2) ON CONFLICT (clerk_id,location_id) DO NOTHING`, [item.AddedByClerkId, payload.LocationId ?? null]);
        }
        for (const item of (payload.VoidedItems ?? [])) {
            await database_js_1.db.query(`INSERT INTO relay_voided_items (transaction_id,item_id,added_by_clerk_id,datetime_sold,name,quantity,sales_group,individual_gross_price,total_gross_price,total_tax,is_refunded) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, [payload.Id, item.Id ?? null, item.AddedByClerkId ?? null, item.DateTimeSold ?? null, item.Name ?? null, item.Quantity ?? 1, item.SalesGroup ?? null, item.IndividualGrossPrice ?? 0, item.TotalGrossPrice ?? 0, item.TotalTax ?? 0, item.IsRefunded ?? false]);
        }
        for (const p of (payload.Payments ?? [])) {
            await database_js_1.db.query(`INSERT INTO relay_transaction_payments (transaction_id,amount,method,payment_datetime) VALUES ($1,$2,$3,$4)`, [payload.Id, p.Amount ?? 0, p.Method ?? null, p.PaymentDateTime ?? null]);
        }
        for (const w of (payload.WastedItems ?? [])) {
            await database_js_1.db.query('INSERT INTO relay_wasted_items (transaction_id,item_data) VALUES ($1,$2)', [payload.Id, JSON.stringify(w)]);
        }
        if (payload.ClosedByClerkId)
            await database_js_1.db.query(`INSERT INTO relay_clerk_mappings (clerk_id,location_id) VALUES ($1,$2) ON CONFLICT (clerk_id,location_id) DO NOTHING`, [payload.ClosedByClerkId, payload.LocationId ?? null]);
        await database_js_1.db.query('UPDATE relay_raw_events SET processed = true WHERE id = $1', [rawId]);
        ok(res, { status: 'ok', transactionId: payload.Id });
    }
    catch (e) {
        next(e);
    }
});
router.get('/webhooks/relay/status', auth, async (req, res, next) => {
    try {
        const stats = await database_js_1.db.query(`SELECT COUNT(*) AS total_transactions, COUNT(DISTINCT location_id) AS locations, COUNT(DISTINCT closed_by_clerk_id) AS clerks, MIN(business_date) AS earliest, MAX(business_date) AS latest FROM relay_transactions`);
        const unmatched = await database_js_1.db.query(`SELECT COUNT(*) AS unmatched_clerks FROM relay_clerk_mappings WHERE team_member_id IS NULL`);
        ok(res, { ...stats.rows[0], ...unmatched.rows[0] });
    }
    catch (e) {
        next(e);
    }
});
// Serve Relay API key to authenticated Fox ITC admins only
router.get('/connectors/relay/key', auth, async (req, res, next) => {
    try {
        const user = req.user;
        if (user.role !== 'admin')
            return err(res, 'Admin only', 403);
        const key = process.env['RELAY_API_KEY'];
        if (!key)
            return err(res, 'Key not configured', 404);
        ok(res, { key });
    }
    catch (e) {
        next(e);
    }
});

router.get('/metrics/trail/breakdown', auth, async (req, res, next) => {
  try {
    const week = req.query['weekEnding'] || (() => {
      const d = new Date(); const day = d.getDay();
      const sun = new Date(d); sun.setDate(d.getDate() - (day === 0 ? 0 : day));
      return sun.toISOString().split('T')[0];
    })();
    // Fall back to latest available week if requested week not found
    const latestWeek = await database_js_1.db.query(
      "SELECT TO_CHAR(MAX(week_ending), 'YYYY-MM-DD') as latest FROM trail_venue_metrics"
    ).catch(() => ({ rows: [{}] }));
    const latestStr = latestWeek.rows[0]?.latest || week;
    const effectiveWeek = week <= latestStr ? week : latestStr;
    const areas = await database_js_1.db.query(
      'SELECT m.*, v.name AS venue_name FROM trail_venue_metrics m JOIN venues v ON v.id = m.venue_id WHERE m.week_ending = $1 ORDER BY v.name, m.area',
      [effectiveWeek]
    ).catch(() => ({ rows: [] }));
    const summary = await database_js_1.db.query(
      'SELECT v.name AS venue_name, m.venue_id, SUM(m.total_tasks) AS total_tasks, SUM(m.completed_tasks) AS completed_tasks, ROUND(AVG(m.completion_rate)::numeric, 2) AS avg_completion_rate, ROUND(AVG(m.trail_score)::numeric, 2) AS combined_trail_score FROM trail_venue_metrics m JOIN venues v ON v.id = m.venue_id WHERE m.week_ending = $1 GROUP BY v.name, m.venue_id ORDER BY combined_trail_score DESC',
      [week]
    ).catch(() => ({ rows: [] }));
    ok(res, { areas: areas.rows, summary: summary.rows });
  } catch (e) { next(e); }
});



router.post('/audit', auth, async (req, res, next) => {
  try {
    const { eventType, source, description, metadata, venueId } = req.body;
    await database_js_1.db.query(
      'INSERT INTO audit_log (event_type, source, description, metadata, venue_id) VALUES ($1,$2,$3,$4,$5)',
      [eventType, source || 'The Club', description, JSON.stringify(metadata||{}), venueId||null]
    );
    ok(res, { logged: true });
  } catch(e) { next(e); }
});

// Recent transactions with items
router.get('/transactions/recent', auth, async (req, res, next) => {
  try {
    const limit = parseInt(req.query['limit']) || 20;
    const txns = await database_js_1.db.query(
      'SELECT t.id, t.location_id, t.business_date, t.datetime_opened, t.datetime_closed, t.covers, t.total_gross_item_cost, t.closed_by_clerk_id, t.seating_area, t.received_at FROM relay_transactions t ORDER BY t.received_at DESC LIMIT $1',
      [limit]
    ).catch(() => ({ rows: [] }));

    // Get items for each transaction
    const result = [];
    for (const tx of txns.rows) {
      const items = await database_js_1.db.query(
        'SELECT name, sales_group, added_by_clerk_id, quantity, total_gross_price FROM relay_sold_items WHERE transaction_id = $1',
        [tx.id]
      ).catch(() => ({ rows: [] }));
      result.push({ ...tx, items: items.rows });
    }
    ok(res, result);
  } catch(e) { next(e); }
});

// Sync status — last sync times and clerk discovery
router.get('/sync/status', auth, async (req, res, next) => {
  try {
    const trailSync = await database_js_1.db.query(
      'SELECT MAX(synced_at) AS last_sync, MAX(week_ending) AS last_week FROM trail_venue_metrics'
    ).catch(() => ({ rows: [{}] }));

    const relayStatus = await database_js_1.db.query(
      'SELECT COUNT(*) AS total, MAX(received_at) AS last_received FROM relay_raw_events'
    ).catch(() => ({ rows: [{}] }));

    const clerks = await database_js_1.db.query(
      'SELECT clerk_id, location_id, created_at, team_member_id FROM relay_clerk_mappings ORDER BY created_at DESC'
    ).catch(() => ({ rows: [] }));

    ok(res, {
      trail: {
        lastSync:  trailSync.rows[0]?.last_sync  || null,
        lastWeek:  trailSync.rows[0]?.last_week  || null,
      },
      relay: {
        totalEvents:  Number(relayStatus.rows[0]?.total) || 0,
        lastReceived: relayStatus.rows[0]?.last_received || null,
      },
      clerks: clerks.rows,
    });
  } catch(e) { next(e); }
});


// Audit log - builds from real data across multiple tables

router.get('/audit', auth, async (req, res, next) => {
  try {
    const limit = parseInt(req.query['limit']) || 100;
    // Also pull from relay_raw_events and clerk_mappings for a richer audit view
    const events = [];

    // Relay transactions received
    const txns = await database_js_1.db.query(
      "SELECT 'WEBHOOK_RECEIVED' as event_type, 'Relay (Access EPOS)' as source, received_at as created_at, 'Transaction received — location ' || location_id || ' · £' || total_gross_item_cost as description FROM relay_transactions WHERE id != '550e8400-e29b-41d4-a716-446655440000' ORDER BY received_at DESC LIMIT 50"
    ).catch(() => ({ rows: [] }));
    events.push(...txns.rows);

    // Clerk discoveries
    const clerks = await database_js_1.db.query(
      "SELECT 'CLERK_DISCOVERED' as event_type, 'Relay (Access EPOS)' as source, created_at, 'New clerk discovered — ID ' || clerk_id || ' at location ' || location_id as description FROM relay_clerk_mappings ORDER BY created_at DESC LIMIT 20"
    ).catch(() => ({ rows: [] }));
    events.push(...clerks.rows);

    // Trail syncs from trail_venue_metrics
    const trail = await database_js_1.db.query(
      "SELECT 'TRAIL_SYNC' as event_type, 'Trail' as source, MAX(synced_at) as created_at, 'Trail sync completed — week ending ' || week_ending::text || ' · ' || SUM(total_tasks) || ' tasks' as description FROM trail_venue_metrics GROUP BY week_ending ORDER BY week_ending DESC LIMIT 10"
    ).catch(() => ({ rows: [] }));
    events.push(...trail.rows);

    // Sort all events by date
    events.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    ok(res, events.slice(0, limit));
  } catch(e) { next(e); }
});

// Recent transactions with items
router.get('/transactions/recent', auth, async (req, res, next) => {
  try {
    const limit = parseInt(req.query['limit']) || 20;
    const txns = await database_js_1.db.query(
      'SELECT t.id, t.location_id, t.business_date, t.datetime_opened, t.datetime_closed, t.covers, t.seating_area, t.total_gross_item_cost, t.total_net_item_cost, t.closed_by_clerk_id, t.terminal_id, t.received_at FROM relay_transactions t ORDER BY t.received_at DESC LIMIT $1',
      [limit]
    ).catch(() => ({ rows: [] }));
    const result = [];
    for (const tx of txns.rows) {
      const items = await database_js_1.db.query(
        'SELECT name, sales_group, added_by_clerk_id, quantity, total_gross_price FROM relay_sold_items WHERE transaction_id = $1',
        [tx.id]
      ).catch(() => ({ rows: [] }));
      result.push({ ...tx, items: items.rows });
    }
    ok(res, result);
  } catch(e) { next(e); }
});

// Sync status
router.get('/sync/status', auth, async (req, res, next) => {
  try {
    const trail = await database_js_1.db.query(
      'SELECT MAX(synced_at) AS last_sync, MAX(week_ending) AS last_week FROM trail_venue_metrics'
    ).catch(() => ({ rows: [{}] }));
    const relay = await database_js_1.db.query(
      'SELECT COUNT(*) AS total, MAX(received_at) AS last_received FROM relay_raw_events'
    ).catch(() => ({ rows: [{}] }));
    const clerks = await database_js_1.db.query(
      'SELECT cm.clerk_id, cm.location_id, cm.created_at, cm.team_member_id, tm.first_name, tm.last_name FROM relay_clerk_mappings cm LEFT JOIN team_members tm ON tm.id = cm.team_member_id ORDER BY cm.created_at DESC'
    ).catch(() => ({ rows: [] }));
    ok(res, {
      trail: { lastSync: trail.rows[0]?.last_sync||null, lastWeek: trail.rows[0]?.last_week||null },
      relay: { totalEvents: Number(relay.rows[0]?.total)||0, lastReceived: relay.rows[0]?.last_received||null },
      clerks: clerks.rows,
    });
  } catch(e) { next(e); }
});

// Venue mapping - save a location to venue mapping
router.post('/venues/map', auth, async (req, res, next) => {
  try {
    const { locationId, venueId, connector } = req.body;
    if (!locationId || !venueId) return err(res, 'locationId and venueId required', 400);
    await database_js_1.db.query(`
      CREATE TABLE IF NOT EXISTS connector_venue_mappings (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        location_id VARCHAR(50) NOT NULL,
        venue_id UUID NOT NULL REFERENCES venues(id),
        connector VARCHAR(50) DEFAULT 'relay',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(location_id, connector)
      )
    `);
    await database_js_1.db.query(
      'INSERT INTO connector_venue_mappings (location_id, venue_id, connector) VALUES ($1,$2,$3) ON CONFLICT (location_id, connector) DO UPDATE SET venue_id = EXCLUDED.venue_id',
      [locationId, venueId, connector||'relay']
    );
    ok(res, { message: 'Venue mapped successfully', locationId, venueId });
  } catch(e) { next(e); }
});

// Get venue mappings
router.get('/venues/mappings', auth, async (req, res, next) => {
  try {
    await database_js_1.db.query(`
      CREATE TABLE IF NOT EXISTS connector_venue_mappings (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        location_id VARCHAR(50) NOT NULL,
        venue_id UUID NOT NULL REFERENCES venues(id),
        connector VARCHAR(50) DEFAULT 'relay',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(location_id, connector)
      )
    `);
    const result = await database_js_1.db.query(
      'SELECT m.*, v.name AS venue_name FROM connector_venue_mappings m JOIN venues v ON v.id = m.venue_id ORDER BY m.created_at DESC'
    ).catch(() => ({ rows: [] }));
    ok(res, result.rows);
  } catch(e) { next(e); }
});




// Transaction summary
router.get('/transactions/summary', auth, async (req, res, next) => {
  try {
    const { period, locationId, from, to } = req.query;
    const locMap = {griffin:'0001', taprun:'0002', longhop:'0003'};
    const locId = locationId && locationId !== 'all' ? (locMap[locationId] || locationId) : null;
    const locWhere = locId ? " AND location_id = '" + locId + "'" : '';

    // Overall summary
    const result = await database_js_1.db.query(
      "SELECT COUNT(*) AS total_transactions," +
      " COALESCE(SUM(total_net_item_cost),0) AS total_revenue," +
      " COALESCE(SUM(CASE WHEN DATE(datetime_opened AT TIME ZONE 'Europe/London')=CURRENT_DATE THEN 1 ELSE 0 END),0) AS today_transactions," +
      " COALESCE(SUM(CASE WHEN DATE(datetime_opened AT TIME ZONE 'Europe/London')=CURRENT_DATE THEN total_net_item_cost ELSE 0 END),0) AS today_revenue," +
      " COALESCE(SUM(CASE WHEN datetime_opened >= NOW() - INTERVAL '7 days' THEN 1 ELSE 0 END),0) AS week_transactions," +
      " COALESCE(SUM(CASE WHEN datetime_opened >= NOW() - INTERVAL '7 days' THEN total_net_item_cost ELSE 0 END),0) AS week_revenue," +
      " COUNT(DISTINCT location_id) AS active_locations" +
      " FROM relay_transactions WHERE 1=1" + locWhere
    ).catch(() => ({ rows: [{}] }));

    // Mon-Sun current week by venue
    const weekStart = new Date();
    const dow = weekStart.getDay();
    weekStart.setDate(weekStart.getDate() - (dow === 0 ? 6 : dow - 1));
    weekStart.setHours(0,0,0,0);
    const weekStartStr = weekStart.toISOString().split('T')[0];

    const byVenueR = await database_js_1.db.query(
      "SELECT t.location_id, v.name as venue_name," +
      " COUNT(*) as transactions," +
      " ROUND(SUM(t.total_net_item_cost)::numeric,2) as net_revenue" +
      " FROM relay_transactions t" +
      " JOIN connector_venue_mappings cvm ON cvm.location_id=t.location_id AND cvm.connector='relay'" +
      " JOIN venues v ON v.id=cvm.venue_id" +
      " WHERE (t.datetime_opened AT TIME ZONE 'Europe/London')::date >= $1" +
      " GROUP BY t.location_id, v.name ORDER BY t.location_id",
      [weekStartStr]
    ).catch(() => ({ rows: [] }));

    ok(res, { ...result.rows[0], byVenue: byVenueR.rows });
  } catch(e) { next(e); }
});

// AI insights proxy - routes Claude API calls server-side to avoid CORS
router.post('/ai/insights', auth, async (req, res, next) => {
  try {
    const { prompt } = req.body;
    if (!prompt) return err(res, 'prompt required', 400);
    const axios = (await import('axios')).default;
    const r = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY || '',
        'anthropic-version': '2023-06-01'
      },
      timeout: 30000
    });
    ok(res, { content: r.data.content });
  } catch(e) {
    const msg = e.response?.data?.error?.message || e.message;
    err(res, 'AI error: ' + msg, 500);
  }
});

// Selector metrics - get all
router.get('/selector/metrics', auth, async (req, res, next) => {
  try {
    const result = await database_js_1.db.query(
      'SELECT * FROM selector_metrics ORDER BY category, weight DESC'
    ).catch(() => ({ rows: [] }));
    ok(res, result.rows);
  } catch(e) { next(e); }
});

// Selector metrics - update single metric
router.put('/selector/metrics/:key', auth, async (req, res, next) => {
  try {
    const { key } = req.params;
    const { target, weight, is_active, name, notes } = req.body;
    await database_js_1.db.query(
      'UPDATE selector_metrics SET target=$1, weight=$2, is_active=$3, name=$4, notes=$5, updated_at=NOW() WHERE metric_key=$6',
      [target, weight, is_active, name, notes, key]
    );
    ok(res, { updated: key });
  } catch(e) { next(e); }
});

// Selector metrics with computed pub-level averages
// Filters: period (7d|14d|30d|90d), venue (all|griffin|taprun|longhop)
router.get('/selector/metrics/with-averages', auth, async (req, res, next) => {
  try {
    const { period, venue } = req.query;
    const intervalMap = { '7d': '7 days', '14d': '14 days', '30d': '30 days', '90d': '90 days' };
    const interval = intervalMap[period] || '7 days';
    const venueMap = { 'griffin': '0001', 'taprun': '0002', 'longhop': '0003' };
    const locId = venueMap[venue] || null;

    // Get all metrics
    const metricsR = await database_js_1.db.query(
      'SELECT * FROM selector_metrics ORDER BY weight DESC, metric_key'
    );

    // Aggregate raw data using same shape as per-clerk aggregator
    const params = [];
    let where = "WHERE 1=1 AND si.datetime_sold >= NOW() - INTERVAL '" + interval + "'";
    if (locId) {
      params.push(locId);
      where += ' AND t.location_id=$' + params.length;
    }

    const aggR = await database_js_1.db.query(
      "SELECT " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='31' AND si.individual_net_price>=5),0) as mains, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='32'),0) as sides, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='29'),0) as nibbles, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='30'),0) as starters, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('33','35')),0) as desserts, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('1','2','3','4','5','6','8','9','10','15','17','18','19','21','22','23','26','27','28','38')),0) as drinks, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('3','4','5','6') AND (si.individual_net_price>40 OR (LOWER(si.name) LIKE 'btl%' AND si.individual_net_price>25))),0) as prem_wine, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('8','15')),0) as spirits, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('8','9','10') AND LOWER(si.name) LIKE '%dbl%'),0) as dbl_spirits, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('3','4','5','6') AND LOWER(si.name) LIKE '%250ml%'),0) as lg_wine, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('3','4','5','6')),0) as all_wine, " +
      "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('3','4','5','6')),0) as wine_net_rev, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE LOWER(si.name) LIKE '%water%' AND si.sales_group NOT IN ('30000','20')),0) as water, " +
      "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('1','2','3','4','5','6','8','9','10','15','17','18','19','21','22','23','26','27','28','38')),0) as wet_rev, " +
      "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('29','30','31','32','33','34','35') AND si.individual_net_price>0),0) as dry_rev, " +
      "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('29','30','31','32','33','34','35') AND si.individual_net_price>=0),0) as food_rev " +
      "FROM relay_transactions t JOIN relay_sold_items si ON si.transaction_id=t.id " + where,
      params
    );
    const m = aggR.rows[0] || {};
    m.est_hours = 0; // will be computed if needed below

    // Estimated labour hours over the same period+venue (for rev_per_labour_hour)
    let hoursWhere = "WHERE rp.pay_date >= NOW()::date - INTERVAL '" + interval + "'";
    const hoursParams = [];
    if (locId) {
      hoursParams.push(locId);
      hoursWhere += ' AND rp.location_id=$' + hoursParams.length;
    }
    const hoursR = await database_js_1.db.query(
      "SELECT COALESCE(SUM(CASE " +
      "WHEN rp.hourly_rate > 5 AND NOT rp.is_salaried THEN rp.basic_pay / rp.hourly_rate " +
      "WHEN rp.is_salaried AND rp.total_pay > 0 THEN rp.total_pay / 12.21 " +
      "ELSE 0 END), 0) AS est_hours FROM rotaready_pay rp " + hoursWhere,
      hoursParams
    ).catch(() => ({ rows: [{ est_hours: 0 }] }));
    m.est_hours = Number(hoursR.rows[0]?.est_hours || 0);

    // Compute actual for each metric using existing calculators
    const result = metricsR.rows.map(metric => {
      const calc = METRIC_CALCULATORS[metric.metric_key];
      const actual_average = calc ? calc.actual(m) : null;
      const target = Number(metric.target);
      const direction = metric.direction;
      let status = 'unknown';
      if (actual_average !== null && target > 0) {
        const ratio = actual_average / target;
        if (direction === 'positive') {
          status = ratio >= 1 ? 'green' : ratio >= 0.9 ? 'amber' : 'red';
        } else {
          status = ratio <= 1 ? 'green' : ratio <= 1.1 ? 'amber' : 'red';
        }
      }
      return {
        metric_key: metric.metric_key,
        category: metric.category,
        name: metric.name,
        direction: metric.direction,
        target: metric.target,
        weight: metric.weight,
        is_active: metric.is_active,
        notes: metric.notes,
        actual_average,
        status,
        period_used: period || '7d',
        venue_used: venue || 'all'
      };
    });

    ok(res, { metrics: result, raw: { ...m, est_hours: m.est_hours }, filters: { period: period || '7d', venue: venue || 'all' } });
  } catch(e) { next(e); }
});

// Pub vs Pub league table - one row per venue with score + actuals
router.get('/league/pubs', auth, async (req, res, next) => {
  try {
    const { period, metrics: metricsFilter } = req.query;
    const intervalMap = { '7d': '7 days', '14d': '14 days', '30d': '30 days', '90d': '90 days' };
    const interval = intervalMap[period] || '7 days';

    const venues = [
      { id: 'griffin', name: 'The Griffin Inn', short: 'GRI', location_id: '0001' },
      { id: 'taprun',  name: 'The Tap & Run',   short: 'TAP', location_id: '0002' },
      { id: 'longhop', name: 'The Long Hop',    short: 'HOP', location_id: '0003' }
    ];

    // Get all active metrics
    const metricsR = await database_js_1.db.query(
      'SELECT * FROM selector_metrics WHERE is_active=true ORDER BY weight DESC, metric_key'
    );
    let activeMetrics = metricsR.rows;

    // Optional filter to specific metric_keys
    if (metricsFilter) {
      const wanted = String(metricsFilter).split(',').map(s => s.trim()).filter(Boolean);
      if (wanted.length > 0) {
        activeMetrics = activeMetrics.filter(m => wanted.includes(m.metric_key));
      }
    }

    const totalWeight = activeMetrics.reduce((sum, m) => sum + Number(m.weight), 0);

    // For each venue, run the same aggregation as with-averages
    const result = [];
    for (const v of venues) {
      const aggR = await database_js_1.db.query(
        "SELECT " +
        "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='31' AND si.individual_net_price>=5),0) as mains, " +
        "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='32'),0) as sides, " +
        "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='29'),0) as nibbles, " +
        "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='30'),0) as starters, " +
        "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('33','35')),0) as desserts, " +
        "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('1','2','3','4','5','6','8','9','10','15','17','18','19','21','22','23','26','27','28','38')),0) as drinks, " +
        "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('3','4','5','6') AND (si.individual_net_price>40 OR (LOWER(si.name) LIKE 'btl%' AND si.individual_net_price>25))),0) as prem_wine, " +
        "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('8','15')),0) as spirits, " +
        "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('8','9','10') AND LOWER(si.name) LIKE '%dbl%'),0) as dbl_spirits, " +
        "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('3','4','5','6') AND LOWER(si.name) LIKE '%250ml%'),0) as lg_wine, " +
        "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('3','4','5','6')),0) as all_wine, " +
        "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('3','4','5','6')),0) as wine_net_rev, " +
        "COALESCE(SUM(si.quantity) FILTER (WHERE LOWER(si.name) LIKE '%water%' AND si.sales_group NOT IN ('30000','20')),0) as water, " +
        "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('1','2','3','4','5','6','8','9','10','15','17','18','19','21','22','23','26','27','28','38')),0) as wet_rev, " +
        "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('29','30','31','32','33','34','35') AND si.individual_net_price>0),0) as dry_rev, " +
        "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('29','30','31','32','33','34','35') AND si.individual_net_price>=0),0) as food_rev " +
        "FROM relay_transactions t JOIN relay_sold_items si ON si.transaction_id=t.id " +
        "WHERE si.datetime_sold >= NOW() - INTERVAL '" + interval + "' AND t.location_id=$1",
        [v.location_id]
      );
      const m = aggR.rows[0] || {};

      // Compute estimated labour hours for this venue + period
      const hoursR = await database_js_1.db.query(
        "SELECT COALESCE(SUM(CASE " +
        "WHEN rp.hourly_rate > 5 AND NOT rp.is_salaried THEN rp.basic_pay / rp.hourly_rate " +
        "WHEN rp.is_salaried AND rp.total_pay > 0 THEN rp.total_pay / 12.21 " +
        "ELSE 0 END), 0) AS est_hours FROM rotaready_pay rp " +
        "WHERE rp.pay_date >= NOW()::date - INTERVAL '" + interval + "' AND rp.location_id=$1",
        [v.location_id]
      ).catch(() => ({ rows: [{ est_hours: 0 }] }));
      m.est_hours = Number(hoursR.rows[0]?.est_hours || 0);
      m.named_review = 0; // not venue-level, set to 0 to avoid breaking calculator

      // Compute actuals + scores per metric
      const metric_values = {};
      let weightedScore = 0;
      for (const metric of activeMetrics) {
        const calc = METRIC_CALCULATORS[metric.metric_key];
        if (!calc) continue;
        const actual = calc.actual(m);
        const target = Number(metric.target);
        const direction = metric.direction;
        const rawScore = scoreMetric(actual, target, direction);
        const status = rawScore >= 80 ? 'green' : rawScore >= 50 ? 'amber' : 'red';
        metric_values[metric.metric_key] = {
          actual,
          target,
          status,
          direction,
          weight: metric.weight,
          name: metric.name,
          score: Math.round(rawScore)
        };
        weightedScore += rawScore * (Number(metric.weight) / totalWeight);
      }

      result.push({
        venue_id: v.id,
        venue_name: v.name,
        venue_short: v.short,
        location_id: v.location_id,
        score: Math.round(weightedScore * 10) / 10,
        tier: weightedScore < 60 ? 'Club Player' : weightedScore < 80 ? 'County Player' : 'Test Player',
        metrics: metric_values
      });
    }

    // Sort by score descending and add rank
    result.sort((a, b) => b.score - a.score);
    result.forEach((r, i) => { r.rank = i + 1; });

    ok(res, { league: result, period: period || '7d', metric_count: activeMetrics.length, total_weight: totalWeight });
  } catch(e) { next(e); }
});

// Pub trend - weekly scores for last N weeks
router.get('/league/pubs/trend', auth, async (req, res, next) => {
  try {
    const weeks = Math.min(Math.max(parseInt(req.query.weeks) || 8, 1), 12);
    const venues = [
      { id: 'griffin', name: 'The Griffin Inn', short: 'GRI', location_id: '0001' },
      { id: 'taprun',  name: 'The Tap & Run',   short: 'TAP', location_id: '0002' },
      { id: 'longhop', name: 'The Long Hop',    short: 'HOP', location_id: '0003' }
    ];

    // Active metrics
    const metricsR = await database_js_1.db.query("SELECT * FROM selector_metrics WHERE is_active=true ORDER BY weight DESC");
    const activeMetrics = metricsR.rows;
    const totalWeight = activeMetrics.reduce((sum, m) => sum + Number(m.weight), 0);

    // Build week ranges (Mon-Sun, ending most recent)
    const weekRanges = [];
    const now = new Date();
    const dayOfWeek = (now.getUTCDay() + 6) % 7; // Mon=0..Sun=6
    const lastSunday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - dayOfWeek - 1));
    
    for (let w = 0; w < weeks; w++) {
      const sun = new Date(lastSunday); sun.setUTCDate(lastSunday.getUTCDate() - w*7);
      const mon = new Date(sun); mon.setUTCDate(sun.getUTCDate() - 6);
      weekRanges.push({
        week_ending: sun.toISOString().slice(0,10),
        start: mon.toISOString().slice(0,10),
        end: sun.toISOString().slice(0,10)
      });
    }
    weekRanges.reverse(); // oldest first

    // For each week+venue: aggregate, score, return
    const result = [];
    for (const wk of weekRanges) {
      const weekData = { week_ending: wk.week_ending, week_start: wk.start, scores: {} };
      
      for (const v of venues) {
        const aggR = await database_js_1.db.query(
          "SELECT " +
          "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='31' AND si.individual_net_price>=5),0) as mains, " +
          "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='32'),0) as sides, " +
          "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='29'),0) as nibbles, " +
          "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='30'),0) as starters, " +
          "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('33','35')),0) as desserts, " +
          "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('1','2','3','4','5','6','8','9','10','15','17','18','19','21','22','23','26','27','28','38')),0) as drinks, " +
          "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('3','4','5','6') AND (si.individual_net_price>40 OR (LOWER(si.name) LIKE 'btl%' AND si.individual_net_price>25))),0) as prem_wine, " +
          "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('8','15')),0) as spirits, " +
          "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('8','9','10') AND LOWER(si.name) LIKE '%dbl%'),0) as dbl_spirits, " +
          "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('3','4','5','6') AND LOWER(si.name) LIKE '%250ml%'),0) as lg_wine, " +
          "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('3','4','5','6')),0) as all_wine, " +
          "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('3','4','5','6')),0) as wine_net_rev, " +
          "COALESCE(SUM(si.quantity) FILTER (WHERE LOWER(si.name) LIKE '%water%' AND si.sales_group NOT IN ('30000','20')),0) as water, " +
          "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('1','2','3','4','5','6','8','9','10','15','17','18','19','21','22','23','26','27','28','38')),0) as wet_rev, " +
          "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('29','30','31','32','33','34','35') AND si.individual_net_price>0),0) as dry_rev " +
          "FROM relay_transactions t JOIN relay_sold_items si ON si.transaction_id=t.id " +
          "WHERE si.datetime_sold >= $1::date AND si.datetime_sold < ($2::date + INTERVAL '1 day') AND t.location_id=$3",
          [wk.start, wk.end, v.location_id]
        );
        const m = aggR.rows[0] || {};

        // Hours for this week + venue
        const hoursR = await database_js_1.db.query(
          "SELECT COALESCE(SUM(CASE " +
          "WHEN rp.hourly_rate > 5 AND NOT rp.is_salaried THEN rp.basic_pay / rp.hourly_rate " +
          "WHEN rp.is_salaried AND rp.total_pay > 0 THEN rp.total_pay / 12.21 " +
          "ELSE 0 END), 0) AS est_hours FROM rotaready_pay rp " +
          "WHERE rp.pay_date >= $1::date AND rp.pay_date <= $2::date AND rp.location_id=$3",
          [wk.start, wk.end, v.location_id]
        ).catch(() => ({ rows: [{ est_hours: 0 }] }));
        m.est_hours = Number(hoursR.rows[0]?.est_hours || 0);
        m.named_review = 0;

        // Compute score (weighted)
        let weighted = 0;
        let hasData = Number(m.dry_rev || 0) > 0;
        for (const metric of activeMetrics) {
          const calc = METRIC_CALCULATORS[metric.metric_key];
          if (!calc) continue;
          const actual = calc.actual(m);
          weighted += scoreMetric(actual, Number(metric.target), metric.direction) * (Number(metric.weight) / totalWeight);
        }
        weekData.scores[v.id] = hasData ? Math.round(weighted * 10) / 10 : null;
      }
      result.push(weekData);
    }

    ok(res, { weeks: result, weeks_requested: weeks, venues: venues.map(v => ({ id: v.id, name: v.name, short: v.short })) });
  } catch(e) { next(e); }
});

// Service bands - get
router.get('/selector/bands', auth, async (req, res, next) => {
  try {
    await database_js_1.db.query(`
      CREATE TABLE IF NOT EXISTS selector_service_bands (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        venue_id UUID REFERENCES venues(id),
        band_key VARCHAR(50) NOT NULL,
        name VARCHAR(100) NOT NULL,
        day_type VARCHAR(20) NOT NULL,
        start_time TIME NOT NULL,
        end_time TIME NOT NULL,
        target_multiplier DECIMAL(4,2) DEFAULT 1.00,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(venue_id, band_key)
      )
    `);
    const result = await database_js_1.db.query(
      'SELECT sb.*, v.name AS venue_name FROM selector_service_bands sb LEFT JOIN venues v ON v.id = sb.venue_id ORDER BY v.name, sb.day_type, sb.start_time'
    ).catch(() => ({ rows: [] }));
    ok(res, result.rows);
  } catch(e) { next(e); }
});

// Service bands - save
router.post('/selector/bands', auth, async (req, res, next) => {
  try {
    const { venueId, bandKey, name, dayType, startTime, endTime, targetMultiplier } = req.body;
    await database_js_1.db.query(`
      CREATE TABLE IF NOT EXISTS selector_service_bands (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        venue_id UUID REFERENCES venues(id),
        band_key VARCHAR(50) NOT NULL,
        name VARCHAR(100) NOT NULL,
        day_type VARCHAR(20) NOT NULL,
        start_time TIME NOT NULL,
        end_time TIME NOT NULL,
        target_multiplier DECIMAL(4,2) DEFAULT 1.00,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(venue_id, band_key)
      )
    `);
    await database_js_1.db.query(
      'INSERT INTO selector_service_bands (venue_id, band_key, name, day_type, start_time, end_time, target_multiplier) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (venue_id, band_key) DO UPDATE SET name=EXCLUDED.name, day_type=EXCLUDED.day_type, start_time=EXCLUDED.start_time, end_time=EXCLUDED.end_time, target_multiplier=EXCLUDED.target_multiplier',
      [venueId, bandKey, name, dayType, startTime, endTime, targetMultiplier || 1.0]
    );
    ok(res, { saved: bandKey });
  } catch(e) { next(e); }
});


// ResDiary webhook verification (GET) + receiver (POST)
router.get('/webhooks/resdiary', async (req, res) => {
  res.status(200).json({ status: 'ok', service: 'ResDiary webhook endpoint' });
});

router.post('/webhooks/resdiary', async (req, res, next) => {
  try {
    const secret = process.env['RESDIARY_WEBHOOK_SECRET'];
    
    // Verify HMAC signature if secret configured
    if (secret) {
      const crypto = await import('crypto');
      const sig = req.headers['x-resdiary-signature'] || '';
      if (sig) {
        // Use raw body string for verification
        const rawBody = req.rawBody || JSON.stringify(req.body);
        const expected = 'sha1=' + crypto.default.createHmac('sha1', secret)
          .update(rawBody)
          .digest('hex');
        console.log('[ResDiary] Sig received:', sig);
        console.log('[ResDiary] Sig expected:', expected);
        if (sig !== expected) {
          console.warn('[ResDiary] Invalid webhook signature - check secret matches');
          // Log but don't reject during testing
          // return res.status(401).json({ error: 'Invalid signature' });
        }
      }
    }

    const payload = req.body;
    // ResDiary structure: Changes[0].ChangeType and Booking.RestaurantName
    const changes = payload.Changes || payload.changes || [];
    const eventType = (changes[0]?.ChangeType || payload.EventType || payload.eventType || 'unknown');
    const booking = payload.Booking || payload.booking || {};
    const restaurantName = booking.RestaurantName || booking.restaurantName || payload.RestaurantName || '';
    const partySize = booking.PartySize || 0;
    const visitDate = booking.VisitDate || '';
    const visitTime = booking.VisitTime || '';
    const reference = booking.Reference || '';
    const status = booking.BookingStatus || booking.ArrivalStatus || '';
    console.log('[ResDiary] Webhook:', eventType, restaurantName, reference, partySize, 'covers', visitDate);

    // Upsert into resdiary_bookings
    if (booking && booking.Id) {
      const locMap = {'The Griffin Inn':'0001','The Tap & Run':'0002','The Long Hop':'0003'};
      const locationId = locMap[restaurantName] || null;
      const customerName = ((booking.Customer?.FirstName||'') + ' ' + (booking.Customer?.Surname||'')).trim();
      database_js_1.db.query(
        "INSERT INTO resdiary_bookings (booking_id, reference, restaurant_name, location_id, visit_date, visit_time, party_size, covers, table_numbers, table_ids, area_ids, booking_status, arrival_status, meal_status, channel_code, customer_email, customer_name, special_requests, booking_duration, customer_spend, last_event_type, last_event_at) " +
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22) " +
        "ON CONFLICT (booking_id) DO UPDATE SET booking_status=EXCLUDED.booking_status, arrival_status=EXCLUDED.arrival_status, meal_status=EXCLUDED.meal_status, table_numbers=EXCLUDED.table_numbers, party_size=EXCLUDED.party_size, covers=EXCLUDED.covers, last_event_type=EXCLUDED.last_event_type, last_event_at=EXCLUDED.last_event_at, updated_at=NOW()",
        [booking.Id, reference, restaurantName, locationId,
         visitDate||null, visitTime||null, partySize||0,
         booking.Covers||booking.covers||null,
         booking.TableNumbers||null, JSON.stringify(booking.TableIds||[]),
         JSON.stringify(booking.AreaIdList||[]),
         booking.BookingStatus||null, booking.ArrivalStatus||null,
         booking.MealStatus||null, booking.ChannelCode||null,
         booking.Customer?.Email||null, customerName||null,
         booking.SpecialRequests||null, booking.BookingDuration||null,
         booking.CustomerSpend||0, eventType, new Date().toISOString()]
      ).catch(e => console.error('[ResDiary] Booking upsert error:', e.message));
    }

    // Store raw event
    await database_js_1.db.query(
      'INSERT INTO resdiary_webhook_events (id, event_type, restaurant_name, payload, received_at) VALUES (uuid_generate_v4(), $1, $2, $3, NOW()) ON CONFLICT DO NOTHING',
      [eventType, restaurantName, JSON.stringify(payload)]
    ).catch(async () => {
      // Create table if not exists
      await database_js_1.db.query(`
        CREATE TABLE IF NOT EXISTS resdiary_webhook_events (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          event_type VARCHAR(100),
          restaurant_name VARCHAR(255),
          payload JSONB,
          processed BOOLEAN DEFAULT false,
          received_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);
      await database_js_1.db.query(
        'INSERT INTO resdiary_webhook_events (id, event_type, restaurant_name, payload) VALUES (uuid_generate_v4(), $1, $2, $3)',
        [eventType, restaurantName, JSON.stringify(payload)]
      );
    });

    // Process booking events
    if (eventType.toLowerCase().includes('booking')) {
      const booking = payload.Booking || payload.booking || payload;
      const covers = booking.Covers || booking.covers || 0;
      const status = booking.Status || booking.status || '';
      const visitDate = booking.VisitDate || booking.visitDate || '';
      const restaurantId = booking.RestaurantId || booking.restaurantId || '';
      console.log('[ResDiary] Booking event:', status, covers, 'covers', visitDate);
    }

    res.status(200).json({ received: true, eventType });
  } catch(e) {
    console.error('[ResDiary webhook]', e.message);
    res.status(200).json({ received: true }); // Always 200 to prevent retries
  }
});

// ResDiary webhook status
router.get('/webhooks/resdiary/status', auth, async (req, res, next) => {
  try {
    const result = await database_js_1.db.query(
      'SELECT COUNT(*) as total, MAX(received_at) as last_received FROM resdiary_webhook_events'
    ).catch(() => ({ rows: [{ total: 0, last_received: null }] }));
    ok(res, {
      endpoint: 'https://theclub.thecatandwickets.com/api/v1/webhooks/resdiary',
      total_events: Number(result.rows[0].total),
      last_received: result.rows[0].last_received
    });
  } catch(e) { next(e); }
});


// Google OAuth - redirect to Google consent screen
router.get('/auth/google', async (req, res) => {
  const clientId = process.env['GOOGLE_CLIENT_ID'];
  const redirectUri = 'https://theclub.thecatandwickets.com/api/v1/auth/google/callback';
  const scope = 'https://www.googleapis.com/auth/business.manage';
  const url = 'https://accounts.google.com/o/oauth2/v2/auth' +
    '?client_id=' + clientId +
    '&redirect_uri=' + encodeURIComponent(redirectUri) +
    '&response_type=code' +
    '&scope=' + encodeURIComponent(scope) +
    '&access_type=offline' +
    '&prompt=consent';
  res.redirect(url);
});

// Google OAuth callback
router.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, error } = req.query;
    if (error) return res.send('Google auth error: ' + error);
    if (!code) return res.send('No code received');

    const axios = (await import('axios')).default;
    const clientId = process.env['GOOGLE_CLIENT_ID'];
    const clientSecret = process.env['GOOGLE_CLIENT_SECRET'];
    const redirectUri = 'https://theclub.thecatandwickets.com/api/v1/auth/google/callback';

    // Exchange code for tokens
    const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
      code, client_id: clientId, client_secret: clientSecret,
      redirect_uri: redirectUri, grant_type: 'authorization_code'
    });

    const { access_token, refresh_token } = tokenRes.data;

    // Store tokens
    await database_js_1.db.query(`
      CREATE TABLE IF NOT EXISTS google_tokens (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        access_token TEXT, refresh_token TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await database_js_1.db.query(
      'DELETE FROM google_tokens'
    );
    await database_js_1.db.query(
      'INSERT INTO google_tokens (access_token, refresh_token) VALUES ($1, $2)',
      [access_token, refresh_token]
    );

    console.log('[Google] OAuth tokens stored successfully');
    res.send('<h2>Google connected successfully!</h2><p>You can close this window.</p><script>window.close();</script>');
  } catch(e) {
    console.error('[Google OAuth]', e.message);
    res.send('Auth error: ' + e.message);
  }
});

// Pull Google reviews for all venues
router.post('/sync/google/reviews', auth, async (req, res, next) => {
  try {
    const axios = (await import('axios')).default;

    // Get stored token
    const tokenRow = await database_js_1.db.query('SELECT access_token, refresh_token FROM google_tokens LIMIT 1').catch(() => ({ rows: [] }));
    if (!tokenRow.rows.length) return err(res, 'Google not connected - visit /api/v1/auth/google to authorise', 400);

    let accessToken = tokenRow.rows[0].access_token;
    const refreshToken = tokenRow.rows[0].refresh_token;

    // Helper: refresh the access token using the refresh token
    async function refreshAccessToken() {
      const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
        client_id: process.env['GOOGLE_CLIENT_ID'],
        client_secret: process.env['GOOGLE_CLIENT_SECRET'],
        refresh_token: refreshToken,
        grant_type: 'refresh_token'
      });
      const newToken = tokenRes.data.access_token;
      await database_js_1.db.query(
        'UPDATE google_tokens SET access_token = $1, updated_at = NOW()',
        [newToken]
      );
      console.log('[Google] Access token refreshed successfully');
      return newToken;
    }

    // Helper: make an authenticated GET request, refreshing token on 401/403
    async function googleGet(url) {
      try {
        return await axios.get(url, { headers: { 'Authorization': 'Bearer ' + accessToken } });
      } catch (e) {
        if (e.response && (e.response.status === 401 || e.response.status === 403) && refreshToken) {
          console.log('[Google] Got ' + e.response.status + ' from ' + url + ', attempting token refresh...');
          if (e.response.data) console.log('[Google] Error detail:', JSON.stringify(e.response.data));
          try {
            accessToken = await refreshAccessToken();
            return await axios.get(url, { headers: { 'Authorization': 'Bearer ' + accessToken } });
          } catch (retryErr) {
            if (retryErr.response && retryErr.response.data) {
              console.error('[Google] Retry failed:', JSON.stringify(retryErr.response.data));
            }
            throw retryErr;
          }
        }
        if (e.response && e.response.data) {
          console.error('[Google] API error ' + e.response.status + ':', JSON.stringify(e.response.data));
        }
        throw e;
      }
    }

    // Get list of locations from Google My Business
    const accountsRes = await googleGet('https://mybusinessaccountmanagement.googleapis.com/v1/accounts');

    const accounts = accountsRes.data.accounts || [];
    if (!accounts.length) return err(res, 'No Google Business accounts found', 404);

    const accountName = accounts[0].name;
    const locationsRes = await googleGet(
      'https://mybusinessbusinessinformation.googleapis.com/v1/' + accountName + '/locations?readMask=name,title,storefrontAddress,metadata'
    );

    const locations = locationsRes.data.locations || [];
    ok(res, { message: 'Sync started', accounts: accounts.length, locations: locations.length, locationNames: locations.map(l => l.title) });

    // Pull reviews for each location in background
    for (const location of locations) {
      try {
        const reviewsRes = await googleGet(
          'https://mybusiness.googleapis.com/v4/' + location.name + '/reviews'
        );
        const reviews = reviewsRes.data.reviews || [];
        console.log('[Google] ' + location.title + ': ' + reviews.length + ' reviews');

        // Store reviews
        await database_js_1.db.query(`
          CREATE TABLE IF NOT EXISTS google_reviews (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            location_name VARCHAR(255),
            reviewer_name VARCHAR(255),
            star_rating VARCHAR(20),
            comment TEXT,
            create_time TIMESTAMPTZ,
            update_time TIMESTAMPTZ,
            reply TEXT,
            named_staff TEXT[],
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(location_name, create_time, reviewer_name)
          )
        `);

        for (const review of reviews) {
          const comment = review.comment || '';
          // Find staff name mentions - will match against team_members once populated
          await database_js_1.db.query(
            'INSERT INTO google_reviews (location_name, reviewer_name, star_rating, comment, create_time, update_time, reply) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING',
            [location.title, review.reviewer?.displayName, review.starRating, comment, review.createTime, review.updateTime, review.reviewReply?.comment]
          );
        }
      } catch(e) {
        console.error('[Google Reviews]', location.title, e.message);
      }
    }
  } catch(e) {
    const detail = e.response && e.response.data && e.response.data.error;
    const msg = detail ? (detail.message || JSON.stringify(detail)) : e.message;
    console.error('[Google Sync Error]', msg);
    return err(res, 'Google API error: ' + msg, e.response ? e.response.status : 500);
  }
});

// Get Google review stats
router.get('/metrics/google/reviews', auth, async (req, res, next) => {
  try {
    const result = await database_js_1.db.query(
      'SELECT location_name, COUNT(*) as total_reviews, COUNT(CASE WHEN star_rating IN (${"5 STARS"}, ${"FIVE"}) THEN 1 END) as five_star FROM google_reviews GROUP BY location_name ORDER BY location_name'
    ).catch(() => ({ rows: [] }));
    ok(res, result.rows);
  } catch(e) { next(e); }
});

// ResDiary test connection
router.post('/sync/resdiary/test', auth, async (req, res, next) => {
  try {
    const u = process.env['RESDIARY_USERNAME'];
    const p = process.env['RESDIARY_PASSWORD'];
    if (!u || !p) return err(res, 'ResDiary credentials not configured', 400);
    const axios = (await import('axios')).default;
    const login = await axios.post('https://login.resdiary.com/api/ConsumerApi/v1/login',
      { username: u, password: p }, { timeout: 15000 });
    const token = login.data?.Token || login.data?.token || login.data;
    const user = await axios.get('https://login.resdiary.com/api/ConsumerApi/v1/CurrentUser',
      { headers: { 'Authorization': 'Bearer ' + token }, timeout: 15000 });
    const diaries = (user.data?.Diaries || user.data?.diaries || []).map(d => d.Name || d.name);
    ok(res, { success: true, message: 'Connected — ' + diaries.length + ' diary(s)', diaries });
  } catch(e) { ok(res, { success: false, message: e.message, diaries: [] }); }
});

// ResDiary sync
router.post('/sync/resdiary', auth, async (req, res, next) => {
  try {
    const { startDate, endDate } = req.body || {};
    const today = new Date().toISOString().split('T')[0];
    const start = startDate || today;
    const end   = endDate   || today;
    ok(res, { message: 'ResDiary sync started for ' + start + ' to ' + end });
    const { createResDiaryConnector } = await import('../connectors/resdiary.js');
    const connector = createResDiaryConnector();
    if (connector) connector.syncAllVenues(start, end).catch(e => console.error('[ResDiary]', e.message));
  } catch(e) { next(e); }
});

// ResDiary metrics
router.get('/metrics/resdiary', auth, async (req, res, next) => {
  try {
    const { startDate, endDate } = req.query;
    const today = new Date().toISOString().split('T')[0];
    const result = await database_js_1.db.query(
      'SELECT m.*, v.name AS venue_name FROM resdiary_daily_metrics m JOIN venues v ON v.id = m.venue_id WHERE m.metric_date BETWEEN $1 AND $2 ORDER BY m.metric_date DESC, v.name',
      [startDate || today, endDate || today]
    ).catch(() => ({ rows: [] }));
    ok(res, result.rows);
  } catch(e) { next(e); }
});

// Trail test connection
router.post('/sync/trail/test', auth, async (req, res, next) => {
  try {
    const apiKey = process.env['TRAIL_API_KEY'];
    if (!apiKey) return err(res, 'Trail not configured', 400);
    const axios = (await import('axios')).default;
    const r = await axios.get('https://web.trailapp.com/api/public/areas/v1/list', {
      headers: { 'API_KEY': apiKey, 'Content-Type': 'application/json' }, timeout: 10000
    });
    const areas = (r.data.data || []).map(a => a.name);
    ok(res, { success: true, message: 'Connected - ' + areas.length + ' areas', areas });
  } catch(e) { ok(res, { success: false, message: e.message, areas: [] }); }
});

// Trail sync
router.post('/sync/trail', auth, async (req, res, next) => {
  try {
    const apiKey = process.env['TRAIL_API_KEY'];
    if (!apiKey) return err(res, 'Trail not configured', 400);
    const today = new Date(); const day = today.getDay();
    const sun = new Date(today); sun.setDate(today.getDate() - (day === 0 ? 0 : day));
    const weekEnding = (req.body && req.body.weekEnding) || sun.toISOString().split('T')[0];
    ok(res, { message: 'Trail sync started for week ending ' + weekEnding });
    const { createTrailConnector } = await import('../connectors/trail.js');
    const connector = createTrailConnector();
    if (connector) connector.syncAllVenues(weekEnding).catch(e => console.error('[Trail]', e.message));
  } catch(e) { next(e); }
});

// Clerk mappings
router.get('/clerks', auth, async (req, res, next) => {
  try {
    const result = await database_js_1.db.query(
      'SELECT cm.*, tm.first_name, tm.last_name, tm.display_name FROM relay_clerk_mappings cm ' +
      'LEFT JOIN team_members tm ON tm.id = cm.team_member_id ORDER BY cm.created_at DESC'
    ).catch(() => ({ rows: [] }));

    // Also return venue-filtered team members for dropdowns
    const locMap = {'0001':'e87b5986-0826-4464-ad62-e55175f9c3c4','0002':'38749619-c192-45d1-806b-2fdc5922adea','0003':'d9657ea0-19c4-4793-9c0c-21fd4179ac56'};
    const { locationId } = req.query;
    const venueId = locationId ? locMap[locationId] : null;
    const whereClause = venueId ? "WHERE venue_id='" + venueId + "' AND is_active=true" : "WHERE is_active=true";
    const members = await database_js_1.db.query(
      'SELECT id, first_name, last_name, display_name, venue_id FROM team_members ' + whereClause + ' ORDER BY first_name, last_name'
    ).catch(() => ({ rows: [] }));

    ok(res, { clerks: result.rows, teamMembers: members.rows });
  } catch(e) { next(e); }
});

router.post('/clerks/:clerkId/match', auth, async (req, res, next) => {
  try {
    const { clerkId } = req.params;
    const { teamMemberId, locationId } = req.body;
    await database_js_1.db.query(
      'UPDATE relay_clerk_mappings SET team_member_id = $1 WHERE clerk_id = $2 AND location_id = $3',
      [teamMemberId, clerkId, locationId]
    );
    ok(res, { message: 'Clerk matched' });
  } catch(e) { next(e); }
});

// Relay key endpoint
router.get('/connectors/relay/key', auth, async (req, res, next) => {
  try {
    const key = process.env['RELAY_API_KEY'];
    if (!key) return err(res, 'Key not configured', 404);
    ok(res, { key });
  } catch(e) { next(e); }
});

// Trail breakdown
router.get('/metrics/trail/breakdown', auth, async (req, res, next) => {
  try {
    const week = req.query['weekEnding'] || (() => {
      const d = new Date(); const day = d.getDay();
      const sun = new Date(d); sun.setDate(d.getDate() - (day === 0 ? 0 : day));
      return sun.toISOString().split('T')[0];
    })();
    // Fall back to latest available week if requested week not found
    const latestWeek = await database_js_1.db.query(
      "SELECT TO_CHAR(MAX(week_ending), 'YYYY-MM-DD') as latest FROM trail_venue_metrics"
    ).catch(() => ({ rows: [{}] }));
    const latestStr = latestWeek.rows[0]?.latest || week;
    const effectiveWeek = week <= latestStr ? week : latestStr;
    const areas = await database_js_1.db.query(
      'SELECT m.*, v.name AS venue_name FROM trail_venue_metrics m JOIN venues v ON v.id = m.venue_id WHERE m.week_ending = $1 ORDER BY v.name, m.area',
      [effectiveWeek]
    ).catch(() => ({ rows: [] }));
    const summary = await database_js_1.db.query(
      'SELECT v.name AS venue_name, m.venue_id, SUM(m.total_tasks) AS total_tasks, SUM(m.completed_tasks) AS completed_tasks, ROUND(AVG(m.completion_rate)::numeric, 2) AS avg_completion_rate, ROUND(AVG(m.trail_score)::numeric, 2) AS combined_trail_score FROM trail_venue_metrics m JOIN venues v ON v.id = m.venue_id WHERE m.week_ending = $1 GROUP BY v.name, m.venue_id ORDER BY combined_trail_score DESC',
      [week]
    ).catch(() => ({ rows: [] }));
    ok(res, { areas: areas.rows, summary: summary.rows });
  } catch(e) { next(e); }
});


// RotaReady - get OAuth token
async function getRotaReadyToken() {
  const axios = (await import('axios')).default;
  const realm = process.env['ROTAREADY_REALM_ID'];
  const key = process.env['ROTAREADY_CONSUMER_KEY'];
  const secret = process.env['ROTAREADY_CONSUMER_SECRET'];
  if (!realm || !key || !secret) throw new Error('RotaReady credentials not configured');
  const auth = Buffer.from(realm+':'+key+':'+secret).toString('base64');
  const r = await axios.post('https://api.rotaready.com/oauth/token',
    'grant_type=client_credentials',
    { headers: { 'Authorization': 'Basic '+auth, 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  return r.data.access_token;
}

// RotaReady - sync staff and venue assignments
async function syncRotaReadyStaff() {
  const axios = (await import('axios')).default;
  const token = await getRotaReadyToken();
  const headers = { 'Authorization': 'Bearer '+token, 'Content-Type': 'application/json', 'Time-Zone': 'Europe/London' };

  // Get all staff
  let allStaff = [], page = 1;
  while (true) {
    const r = await axios.get('https://api.rotaready.com/staff/account/paginated?page='+page+'&limit=50', { headers });
    const users = r.data.users || [];
    allStaff = allStaff.concat(users);
    if (users.length < 50) break;
    page++;
  }

  // Venue entity from appointment object (permission: View Everyone on Employments)
  const userEntity = {};
  allStaff.forEach(s => {
    const appt = s.appointment || {};
    const entityId = (appt.entityId || appt.entity?.id || '').toLowerCase();
    if (entityId) userEntity[s.id] = entityId;
  });

  const venueMap = {'tap':'38749619-c192-45d1-806b-2fdc5922adea','gri':'e87b5986-0826-4464-ad62-e55175f9c3c4','tlh':'d9657ea0-19c4-4793-9c0c-21fd4179ac56'};
  const defaultVenue = 'e87b5986-0826-4464-ad62-e55175f9c3c4';

  let upserted = 0;
  for (const s of allStaff) {
    if (s.firstName === 'Rotaready') continue;
    const entity = userEntity[s.id] || '';
    let venueId = defaultVenue;
    for (const [k, v] of Object.entries(venueMap)) {
      if (entity.startsWith(k)) { venueId = v; break; }
    }
    const initials = ((s.firstName||'X')[0]+(s.lastName||'X')[0]).toUpperCase();
    await database_js_1.db.query(
      "INSERT INTO team_members (venue_id, first_name, last_name, display_name, avatar_initials, avatar_color, rota_id, is_active) " +
      "VALUES ($1,$2,$3,$4,$5,'#4a9b8e',$6,$7) " +
      "ON CONFLICT (rota_id) WHERE rota_id IS NOT NULL DO UPDATE SET first_name=EXCLUDED.first_name, last_name=EXCLUDED.last_name, " +
      "display_name=EXCLUDED.display_name, venue_id=EXCLUDED.venue_id, is_active=EXCLUDED.is_active, updated_at=NOW()",
      [venueId, s.firstName, s.lastName, s.firstName+' '+s.lastName, initials, String(s.id), s.flags.active]
    ).catch(e => console.error('[RotaReady] Upsert error:', e.message));

    // Discover position/group taxonomy as we go - populate position_map
    const appt = s.appointment;
    if (appt?.position?.id) {
      await database_js_1.db.query(
        "INSERT INTO rotaready_position_map (position_id, group_id, position_name, group_name, entity_id, shift_type) " +
        "VALUES ($1, $2, $3, $4, $5, 'other') " +
        "ON CONFLICT (position_id) DO UPDATE SET " +
        "  group_id = EXCLUDED.group_id, " +
        "  position_name = EXCLUDED.position_name, " +
        "  group_name = EXCLUDED.group_name, " +
        "  entity_id = EXCLUDED.entity_id",
        [appt.position.id, appt.groupId, appt.position.name, appt.groupName, appt.entityId]
      ).catch(()=>{});
    }
    upserted++;
  }
  // Sync pay/labour data
  try {
    const now = new Date();
    // Pull rolling 28 days to build history
    const startD = new Date(now);
    startD.setUTCDate(startD.getUTCDate() - 90);
    const startDate = startD.toISOString().split('T')[0];
    const endDate = now.toISOString().split('T')[0];
    console.log('[RotaReady] Pay sync date range:', startDate, 'to', endDate);
    const payR = await axios.get('https://api.rotaready.com/report/signedOffHours?startDate='+startDate+'&endDate='+endDate, {headers});
    const payItems = payR.data?.items || [];
    const entityLoc = {gri:'0001',tap:'0002',tlh:'0003'};
    let paySynced = 0;
    for (const item of payItems) {
      const loc = entityLoc[item.entityId];
      if (!loc) continue;
      for (const w of (item.work||[])) {
        if (!w.representsBasicPay) continue;
        const cp = w.calculatedPay || {};
        const isSalaried = w.payAmount > 100;
        await database_js_1.db.query(
          "INSERT INTO rotaready_pay (user_id, entity_id, location_id, pay_date, basic_pay, total_pay, hours_paid, hourly_rate, is_salaried, position_id, group_id, shift_type) " +
          "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) " +
          "ON CONFLICT (user_id, pay_date, entity_id) DO UPDATE SET basic_pay=$5, total_pay=$6, hours_paid=$7, position_id=$10, group_id=$11, shift_type=$12, synced_at=NOW()",
          [item.userId, item.entityId, loc, item.date?.split('T')[0],
           parseFloat(cp.base||0), parseFloat(cp.totalPay||0),
           isSalaried ? 0 : parseFloat(w.durationPaid||0),
           isSalaried ? 0 : parseFloat(w.payAmount||0), isSalaried,
           item.appointment?.positionId || null,
           item.appointment?.groupId || null,
           null]
        ).catch(()=>{});
        paySynced++;
      }
    }
    console.log('[RotaReady] Pay records synced:', paySynced);
  } catch(e) { console.error('[RotaReady] Pay sync error:', e.message); }

  console.log('[RotaReady] Staff sync complete:', upserted, 'staff processed');

  // Archive team members not seen in RotaReady for 30+ days
  // (they remain in DB but marked inactive - will reactivate on next appearance)
  try {
    const archiveRes = await database_js_1.db.query(
      "UPDATE team_members SET is_active=false " +
      "WHERE is_active=true " +
      "AND rota_id IS NOT NULL " +
      "AND updated_at < NOW() - INTERVAL '30 days' " +
      "AND id NOT IN (SELECT DISTINCT id FROM team_members WHERE updated_at >= NOW() - INTERVAL '30 days')"
    );
    if (archiveRes.rowCount > 0) {
      console.log('[RotaReady] Archived', archiveRes.rowCount, 'inactive staff (30+ days)');
    }
  } catch(e) { console.error('[RotaReady] Archive error:', e.message); }

  return upserted;
}

// RotaReady sync endpoint
router.post('/sync/rotaready', auth, async (req, res, next) => {
  try {
    const count = await syncRotaReadyStaff();
    ok(res, { message: 'RotaReady sync complete', staff_synced: count });
  } catch(e) {
    console.error('[RotaReady]', e.message);
    err(res, 'RotaReady sync failed: '+e.message, 500);
  }
});

// Deep historical backfill - runs chunked 3-month requests against signedOffHours
router.post('/sync/rotaready/backfill', auth, async (req, res, next) => {
  try {
    const { startYear, startMonth } = req.body || {};
    const axios = (await import('axios')).default;
    const token = await getRotaReadyToken();
    const headers = { 'Authorization': 'Bearer '+token, 'Time-Zone': 'Europe/London' };

    // Default chunks: Oct 2023 -> April 2026
    let chunks = req.body?.chunks || [
      ['2023-10-01', '2023-12-31'],
      ['2024-01-01', '2024-03-31'],
      ['2024-04-01', '2024-06-30'],
      ['2024-07-01', '2024-09-30'],
      ['2024-10-01', '2024-12-31'],
      ['2025-01-01', '2025-03-31'],
      ['2025-04-01', '2025-06-30'],
      ['2025-07-01', '2025-09-30'],
      ['2025-10-01', '2025-12-31'],
      ['2026-01-01', '2026-04-30']
    ];

    const entityLoc = {gri:'0001', tap:'0002', tlh:'0003'};
    const summary = [];
    let totalSynced = 0;

    for (const [startDate, endDate] of chunks) {
      const t0 = Date.now();
      let synced = 0;
      try {
        const r = await axios.get('https://api.rotaready.com/report/signedOffHours?startDate='+startDate+'&endDate='+endDate, { headers, validateStatus: () => true });
        if (r.status !== 200) {
          summary.push({ chunk: startDate+'_'+endDate, status: r.status, synced: 0, error: JSON.stringify(r.data).slice(0,150) });
          continue;
        }
        const items = r.data?.items || [];
        for (const item of items) {
          const loc = entityLoc[item.entityId];
          if (!loc) continue;
          for (const w of (item.work||[])) {
            if (!w.representsBasicPay) continue;
            const cp = w.calculatedPay || {};
            const isSalaried = w.payAmount > 100;
            await database_js_1.db.query(
              'INSERT INTO rotaready_pay (user_id, entity_id, location_id, pay_date, basic_pay, total_pay, hours_paid, hourly_rate, is_salaried, position_id, group_id, shift_type) ' +
              'VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ' +
              'ON CONFLICT (user_id, pay_date, entity_id) DO UPDATE SET basic_pay=$5, total_pay=$6, hours_paid=$7, position_id=$10, group_id=$11, shift_type=$12, synced_at=NOW()',
              [item.userId, item.entityId, loc, item.date?.split('T')[0],
               parseFloat(cp.base||0), parseFloat(cp.totalPay||0),
               isSalaried ? 0 : parseFloat(w.durationPaid||0),
               isSalaried ? 0 : parseFloat(w.payAmount||0), isSalaried,
               item.appointment?.positionId || null,
               item.appointment?.groupId || null,
               null]
            ).catch(()=>{});
            synced++;
          }
        }
        summary.push({ chunk: startDate+'_'+endDate, status: 200, items: items.length, synced, ms: Date.now()-t0 });
        totalSynced += synced;
      } catch(e) {
        summary.push({ chunk: startDate+'_'+endDate, error: e.message });
      }
    }

    // Backfill shift_type from position map
    const sR = await database_js_1.db.query(
      'UPDATE rotaready_pay rp SET shift_type = pm.shift_type ' +
      'FROM rotaready_position_map pm ' +
      'WHERE rp.position_id = pm.position_id AND rp.shift_type IS NULL'
    );

    // Final stats
    const stats = await database_js_1.db.query(
      'SELECT MIN(pay_date) AS earliest, MAX(pay_date) AS latest, COUNT(*) AS total_rows, COUNT(*) FILTER (WHERE position_id IS NOT NULL) AS with_position FROM rotaready_pay'
    );

    ok(res, {
      message: 'Backfill complete',
      total_synced: totalSynced,
      shift_type_backfilled_rows: sR.rowCount,
      chunks: summary,
      stats: stats.rows[0]
    });
  } catch(e) {
    console.error('[Backfill]', e.message);
    err(res, 'Backfill failed: '+e.message, 500);
  }
});

// RotaReady status
router.get('/sync/rotaready/status', auth, async (req, res, next) => {
  try {
    const r = await database_js_1.db.query(
      "SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE is_active) as active, " +
      "MAX(updated_at) as last_sync FROM team_members WHERE rota_id IS NOT NULL"
    );
    ok(res, r.rows[0]);
  } catch(e) { next(e); }
});


// Connector status - dynamic status for all connectors
router.get('/connectors/status', auth, async (req, res, next) => {
  try {
    const env = process.env;
    const status = {};
    const relayR = await database_js_1.db.query("SELECT COUNT(*) as total, MAX(received_at) as last_received FROM relay_transactions").catch(()=>({rows:[{}]}));
    status.relay = {status: Number(relayR.rows[0]?.total)>0?'live':'offline', lastSync: relayR.rows[0]?.last_received, total: relayR.rows[0]?.total};
    const trailR = await database_js_1.db.query("SELECT MAX(synced_at) as last_sync, COUNT(*) as total FROM trail_venue_metrics").catch(()=>({rows:[{}]}));
    status.trail = {status: Number(trailR.rows[0]?.total)>0?'connected':'offline', lastSync: trailR.rows[0]?.last_sync};
    const rsdR = await database_js_1.db.query("SELECT COUNT(*) as total, MAX(received_at) as last_received FROM resdiary_webhook_events").catch(()=>({rows:[{}]}));
    const rsdBookingsR = await database_js_1.db.query("SELECT COUNT(*) as total FROM resdiary_bookings").catch(()=>({rows:[{total:0}]}));
    status.resdiary = {
      status: Number(rsdR.rows[0]?.total) > 0 ? 'live' : 'pending',
      webhookEvents: rsdR.rows[0]?.total,
      bookings: rsdBookingsR.rows[0]?.total,
      lastSync: rsdR.rows[0]?.last_received
    };
    const rrOk = !!(env.ROTAREADY_REALM_ID && env.ROTAREADY_CONSUMER_KEY && env.ROTAREADY_CONSUMER_SECRET);
    const rrR = await database_js_1.db.query("SELECT COUNT(*) as total, MAX(updated_at) as last_sync FROM team_members WHERE rota_id IS NOT NULL").catch(()=>({rows:[{}]}));
    status.rotaready = {status: rrOk && Number(rrR.rows[0]?.total)>0?'connected':rrOk?'configured':'offline', lastSync: rrR.rows[0]?.last_sync, staffCount: rrR.rows[0]?.total};
    const gRatingsR = await database_js_1.db.query("SELECT COUNT(*) as venues, MAX(synced_at) as last_sync FROM google_place_ratings").catch(()=>({rows:[{venues:0}]}));
    const gReviewsR = await database_js_1.db.query("SELECT COUNT(*) as total FROM google_reviews").catch(()=>({rows:[{total:0}]}));
    status.google = {
      status: Number(gRatingsR.rows[0]?.venues) > 0 ? 'live' : 'offline',
      venuesCovered: gRatingsR.rows[0]?.venues,
      reviewsStored: gReviewsR.rows[0]?.total,
      lastSync: gRatingsR.rows[0]?.last_sync
    };
    const cplR = await database_js_1.db.query("SELECT COUNT(DISTINCT employee_id) as users, MAX(synced_at) as last_sync FROM cpl_users WHERE active=true").catch(()=>({rows:[{users:0}]}));
    const cplTrainR = await database_js_1.db.query("SELECT COUNT(*) as records FROM cpl_training").catch(()=>({rows:[{records:0}]}));
    status.cpl = {
      status: env.CPL_API_KEY && Number(cplR.rows[0]?.users) > 0 ? 'live' : env.CPL_API_KEY ? 'configured' : 'offline',
      activeUsers: cplR.rows[0]?.users,
      trainingRecords: cplTrainR.rows[0]?.records,
      lastSync: cplR.rows[0]?.last_sync
    };
    ok(res, status);
  } catch(e) { next(e); }
});


// Google Places - sync reviews for all venues using Places API
router.post('/sync/google/places', auth, async (req, res, next) => {
  try {
    const axios = (await import('axios')).default;
    const apiKey = process.env['GOOGLE_PLACES_API_KEY'];
    if (!apiKey) return err(res, 'GOOGLE_PLACES_API_KEY not configured', 400);

    const venues = [
      { placeId: 'ChIJkY6ikuPfeUgRTwYKwMOxnRQ', name: 'The Griffin Inn', locationId: '0001' },
      { placeId: 'ChIJL1fXX1rReUgRoasMv1zsgZI', name: 'Tap & Run', locationId: '0002' },
      { placeId: 'ChIJF_oJeAADekgRpSlCi0O92BI', name: 'The Long Hop', locationId: '0003' },
    ];

    // Get team member names for named mention matching
    const membersRes = await database_js_1.db.query(
      "SELECT first_name, last_name, venue_id FROM team_members WHERE is_active = true"
    );
    const members = membersRes.rows;

    const results = [];
    for (const venue of venues) {
      const r = await axios.get('https://maps.googleapis.com/maps/api/place/details/json', {
        params: {
          place_id: venue.placeId,
          fields: 'name,rating,user_ratings_total,reviews',
          key: apiKey,
          language: 'en'
        }
      });

      const place = r.data.result || {};
      const rating = place.rating || 0;
      const totalReviews = place.user_ratings_total || 0;
      const reviews = place.reviews || [];

      // Store overall rating
      await database_js_1.db.query(
        "INSERT INTO google_place_ratings (location_id, venue_name, rating, total_reviews, synced_at) " +
        "VALUES ($1, $2, $3, $4, NOW()) " +
        "ON CONFLICT (location_id) DO UPDATE SET rating=$3, total_reviews=$4, synced_at=NOW()",
        [venue.locationId, venue.name, rating, totalReviews]
      ).catch(async () => {
        await database_js_1.db.query(`
          CREATE TABLE IF NOT EXISTS google_place_ratings (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            location_id VARCHAR(10) UNIQUE,
            venue_name VARCHAR(255),
            rating NUMERIC(3,1),
            total_reviews INTEGER,
            synced_at TIMESTAMPTZ DEFAULT NOW()
          )
        `);
        await database_js_1.db.query(
          "INSERT INTO google_place_ratings (location_id, venue_name, rating, total_reviews) VALUES ($1,$2,$3,$4) ON CONFLICT (location_id) DO UPDATE SET rating=$3, total_reviews=$4, synced_at=NOW()",
          [venue.locationId, venue.name, rating, totalReviews]
        );
      });

      // Process each review for named mentions
      for (const review of reviews) {
        const text = review.text || '';
        const reviewDate = new Date(review.time * 1000).toISOString();
        
        // Find staff name mentions
        const venueMembers = members.filter(m => {
          const locMap = {'0001':'e87b5986-0826-4464-ad62-e55175f9c3c4','0002':'38749619-c192-45d1-806b-2fdc5922adea','0003':'d9657ea0-19c4-4793-9c0c-21fd4179ac56'};
          return m.venue_id === locMap[venue.locationId];
        });
        const namedStaff = venueMembers
          .filter(m => text.toLowerCase().includes(m.first_name.toLowerCase()) && m.first_name.length > 2)
          .map(m => m.first_name + ' ' + m.last_name);

        await database_js_1.db.query(
          "INSERT INTO google_reviews (location_name, reviewer_name, star_rating, comment, create_time, named_staff) " +
          "VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
          [venue.name, review.author_name, String(review.rating), text, reviewDate, namedStaff]
        ).catch(() => {});
      }

      results.push({ venue: venue.name, rating, totalReviews, reviewsProcessed: reviews.length });
      console.log('[Google Places]', venue.name, rating, totalReviews, 'reviews');
    }

    ok(res, { synced: results });
  } catch(e) {
    console.error('[Google Places]', e.message);
    err(res, 'Google Places error: ' + e.message, 500);
  }
});

// Google place ratings endpoint
router.get('/metrics/google/ratings', auth, async (req, res, next) => {
  try {
    const ratings = await database_js_1.db.query(
      "SELECT location_id, venue_name, rating, previous_rating, total_reviews, previous_total, synced_at FROM google_place_ratings ORDER BY location_id"
    ).catch(() => ({ rows: [] }));
    const reviews = await database_js_1.db.query(
      "SELECT location_name, reviewer_name, star_rating, comment, create_time, named_staff " +
      "FROM google_reviews ORDER BY create_time DESC LIMIT 50"
    ).catch(() => ({ rows: [] }));
    ok(res, { ratings: ratings.rows, reviews: reviews.rows });
  } catch(e) { next(e); }
});


// ── PRODUCT INTELLIGENCE ROUTES ───────────────────────────────────────────────

function getPeriodClause(period) {
  if (period === 'today') return "AND t.datetime_opened >= NOW() - INTERVAL '24 hours'";
  if (period === 'week') return "AND t.datetime_opened >= NOW() - INTERVAL '7 days'";
  if (period === 'month') return "AND t.datetime_opened >= NOW() - INTERVAL '30 days'";
  return "";
}

function getVenueClause(venue) {
  const map = {'griffin':'0001','taprun':'0002','longhop':'0003'};
  const loc = map[venue];
  return loc ? "AND t.location_id = '" + loc + "'" : "";
}

router.get('/products/intel', auth, async (req, res, next) => {
  try {
    const { period, venue } = req.query;
    const pc = getPeriodClause(period);
    const vc = getVenueClause(venue);
    const [mainsR, itemsR, topR, revR, drinkR] = await Promise.all([
      database_js_1.db.query("SELECT SUM(si.quantity) as mains FROM relay_sold_items si JOIN relay_transactions t ON t.id = si.transaction_id WHERE si.sales_group = '31' " + pc + " " + vc),
      database_js_1.db.query("SELECT SUM(si.quantity) as total FROM relay_sold_items si JOIN relay_transactions t ON t.id = si.transaction_id WHERE si.sales_group NOT IN ('30000','20') " + pc + " " + vc),
      database_js_1.db.query("SELECT si.name, SUM(si.quantity) as units FROM relay_sold_items si JOIN relay_transactions t ON t.id = si.transaction_id WHERE si.sales_group NOT IN ('30000','20') " + pc + " " + vc + " GROUP BY si.name ORDER BY units DESC LIMIT 1"),
      database_js_1.db.query("SELECT SUM(t.total_net_item_cost) as net_rev, COUNT(DISTINCT t.closed_by_clerk_id) as clerks FROM relay_transactions t WHERE 1=1 " + pc + " " + vc),
      database_js_1.db.query("SELECT si.name, SUM(si.quantity) as units FROM relay_sold_items si JOIN relay_transactions t ON t.id = si.transaction_id WHERE si.sales_group IN ('1','2','3','4','5','6','8','15') " + pc + " " + vc + " GROUP BY si.name ORDER BY units DESC LIMIT 1"),
    ]);
    ok(res, { mainsSold: Number(mainsR.rows[0]?.mains||0), totalItems: Number(itemsR.rows[0]?.total||0), netRevenue: Number(revR.rows[0]?.net_rev||0).toFixed(2), totalClerks: Number(revR.rows[0]?.clerks||0), topProduct: topR.rows[0]?{name:topR.rows[0].name,units:topR.rows[0].units}:null, topDrink: drinkR.rows[0]?{name:drinkR.rows[0].name,units:drinkR.rows[0].units}:null });
  } catch(e) { next(e); }
});

// ASPH by venue endpoint - all food revenue / mains sold + labour efficiency
router.get('/metrics/asph', auth, async (req, res, next) => {
  try {
    const { period } = req.query;
    const intervalMap = {'today':'1 day','week':'7 days','fortnight':'14 days','month':'28 days','quarter':'90 days'};
    const interval = intervalMap[period] || '7 days';
    
    const r = await database_js_1.db.query(
      "WITH food_metrics AS (" +
      "  SELECT t.location_id, " +
      "  SUM(si.quantity) FILTER (WHERE si.sales_group='31' AND si.individual_net_price >= 5) as mains_sold, " +
      "  ROUND(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('29','30','31','32','33','34','35'))::numeric, 2) as dry_revenue, " +
      "  ROUND(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('1','2','3','4','5','6','8','9','10','15','17','18','19','21','22','23','26','27','28','38'))::numeric, 2) as wet_revenue, " +
      "  ROUND(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('29','30','31','32','33','34','35')) / " +
      "  NULLIF(SUM(si.quantity) FILTER (WHERE si.sales_group='31' AND si.individual_net_price >= 5), 0)::numeric, 2) as asph " +
      "  FROM relay_sold_items si " +
      "  JOIN relay_transactions t ON t.id=si.transaction_id " +
      "  WHERE t.datetime_opened >= NOW() - INTERVAL '" + interval + "' " +
      "  GROUP BY t.location_id" +
      "), " +
      "net_rev AS (" +
      "  SELECT location_id, ROUND(SUM(total_net_item_cost)::numeric, 2) as net_revenue, COUNT(*) as transactions " +
      "  FROM relay_transactions " +
      "  WHERE datetime_opened >= NOW() - INTERVAL '" + interval + "' " +
      "  GROUP BY location_id" +
      "), " +
      "labour AS (" +
      "  SELECT location_id, " +
      "  ROUND(SUM(basic_pay)::numeric, 2) as labour_cost, " +
      "  ROUND(SUM(CASE WHEN hourly_rate > 5 AND NOT is_salaried THEN basic_pay/hourly_rate " +
      "    WHEN is_salaried AND total_pay > 0 THEN total_pay/12.21 ELSE 0 END)::numeric, 1) as est_hours " +
      "  FROM rotaready_pay " +
      "  WHERE pay_date >= NOW() - INTERVAL '" + interval + "' " +
      "  GROUP BY location_id" +
      ") " +
      "SELECT f.location_id, f.mains_sold, f.dry_revenue, f.wet_revenue, f.asph, " +
      "r.net_revenue, r.transactions, " +
      "l.labour_cost, l.est_hours, " +
      "ROUND(r.net_revenue / NULLIF(l.est_hours, 0)::numeric, 2) as rev_per_labour_hour, " +
      "ROUND(l.labour_cost / NULLIF(r.net_revenue, 0) * 100::numeric, 1) as labour_pct " +
      "FROM food_metrics f " +
      "JOIN net_rev r ON r.location_id=f.location_id " +
      "LEFT JOIN labour l ON l.location_id=f.location_id " +
      "ORDER BY f.location_id"
    );
    ok(res, r.rows);
  } catch(e) { next(e); }
});

router.get('/products/leaderboard', auth, async (req, res, next) => {
  try {
    const { period, venue, salesGroup } = req.query;
    const pc = getPeriodClause(period);
    const vc = getVenueClause(venue);
    const sg = salesGroup ? "AND si.sales_group = '" + salesGroup + "'" : "AND si.sales_group NOT IN ('30000','20')";
    const r = await database_js_1.db.query("SELECT si.name, SUM(si.quantity) as units_sold, SUM(si.total_net_price) as net_revenue, COUNT(DISTINCT t.closed_by_clerk_id) as clerks_selling FROM relay_sold_items si JOIN relay_transactions t ON t.id = si.transaction_id WHERE 1=1 " + sg + " " + pc + " " + vc + " GROUP BY si.name ORDER BY units_sold DESC LIMIT 20");
    ok(res, r.rows);
  } catch(e) { next(e); }
});

router.get('/products/search', auth, async (req, res, next) => {
  try {
    const { q, period, venue } = req.query;
    if (!q) return ok(res, { products: [] });
    const pc = getPeriodClause(period);
    const vc = getVenueClause(venue);
    const r = await database_js_1.db.query("SELECT si.name, si.sales_group, SUM(si.quantity) as units_sold, SUM(si.total_net_price) as net_revenue, COUNT(DISTINCT t.closed_by_clerk_id) as clerks_selling FROM relay_sold_items si JOIN relay_transactions t ON t.id = si.transaction_id WHERE LOWER(si.name) LIKE LOWER($1) AND si.sales_group NOT IN ('30000','20') " + pc + " " + vc + " GROUP BY si.name, si.sales_group ORDER BY units_sold DESC LIMIT 10", ['%' + q + '%']);
    ok(res, { products: r.rows });
  } catch(e) { next(e); }
});

router.get('/products/clerks', auth, async (req, res, next) => {
  try {
    const { product, period, venue } = req.query;
    if (!product) return ok(res, []);
    const pc = getPeriodClause(period);
    const vc = getVenueClause(venue);
    const r = await database_js_1.db.query("SELECT t.closed_by_clerk_id as clerk_id, t.location_id, SUM(si.quantity) as units_sold, tm.display_name, v.name as venue_name FROM relay_sold_items si JOIN relay_transactions t ON t.id = si.transaction_id LEFT JOIN relay_clerk_mappings rcm ON rcm.clerk_id = t.closed_by_clerk_id AND rcm.location_id = t.location_id LEFT JOIN team_members tm ON tm.id = rcm.team_member_id LEFT JOIN venues v ON v.id = tm.venue_id WHERE LOWER(si.name) LIKE LOWER($1) AND si.sales_group NOT IN ('30000','20') " + pc + " " + vc + " GROUP BY t.closed_by_clerk_id, t.location_id, tm.display_name, v.name ORDER BY units_sold DESC LIMIT 20", ['%' + product + '%']);
    ok(res, r.rows);
  } catch(e) { next(e); }
});


// ResDiary bookings
router.get('/bookings/resdiary', auth, async (req, res, next) => {
  try {
    const { venue, date, from, to, status, limit, offset } = req.query;
    const locMap = {'griffin':'0001','taprun':'0002','longhop':'0003'};
    const conditions = ["restaurant_name NOT LIKE '%Test%'"];
    const params = [];
    if (venue && locMap[venue]) { params.push(locMap[venue]); conditions.push('location_id=$'+params.length); }
    if (date) { params.push(date); conditions.push('visit_date=$'+params.length); }
    if (from) { params.push(from); conditions.push('visit_date>=$'+params.length); }
    if (to) { params.push(to); conditions.push('visit_date<=$'+params.length); }
    if (status) { params.push(status); conditions.push('booking_status=$'+params.length); }
    const where = 'WHERE '+conditions.join(' AND ');
    const lim = Math.min(parseInt(limit) || 500, 5000);
    const off = parseInt(offset) || 0;
    params.push(lim); const limIdx = params.length;
    params.push(off); const offIdx = params.length;
    const cR = await database_js_1.db.query('SELECT COUNT(*) AS total FROM resdiary_bookings ' + where, params.slice(0, params.length - 2));
    const r = await database_js_1.db.query(
      'SELECT booking_id, reference, restaurant_name, location_id, visit_date, visit_time, party_size, covers, table_numbers, table_ids, area_ids, booking_status, arrival_status, meal_status, channel_code, customer_email, customer_name, special_requests, booking_duration, customer_spend, last_event_type, last_event_at, created_at, updated_at ' +
      'FROM resdiary_bookings ' + where + ' ORDER BY visit_date DESC, visit_time DESC LIMIT $' + limIdx + ' OFFSET $' + offIdx,
      params
    );
    ok(res, { rows: r.rows, total: Number(cR.rows[0].total), limit: lim, offset: off });
  } catch(e) { next(e); }
});

// Today's bookings summary per venue
router.get('/bookings/resdiary/today', auth, async (req, res, next) => {
  try {
    const r = await database_js_1.db.query(
      "SELECT location_id, restaurant_name, " +
      "COUNT(*) as total_bookings, " +
      "SUM(party_size) as total_covers, " +
      "COUNT(*) FILTER (WHERE arrival_status IN ('FullySeated','WaitingInBar','PartiallySeated')) as arrived, " +
      "COUNT(*) FILTER (WHERE meal_status IN ('Closed','Check')) as finished " +
      "FROM resdiary_bookings " +
      "WHERE visit_date = CURRENT_DATE AND restaurant_name NOT LIKE '%Test%' " +
      "GROUP BY location_id, restaurant_name ORDER BY location_id"
    );
    ok(res, r.rows);
  } catch(e) { next(e); }
});


// ── WEATHER + CALENDAR CONTEXT ───────────────────────────────────────────────

// Venue locations for weather API
const VENUE_LOCATIONS = {
  '0001': { name: 'The Griffin Inn', lat: 52.7018, lon: -1.1745 },  // Swithland, Leicestershire
  '0002': { name: 'Tap & Run', lat: 52.8584, lon: -1.0244 },        // Upper Broughton, Nottinghamshire
  '0003': { name: 'The Long Hop', lat: 52.8065, lon: -1.6444 },     // Burton-on-Trent, Staffordshire
};

async function syncWeather() {
  const apiKey = process.env['OPENWEATHER_API_KEY'];
  if (!apiKey) { console.log('[Weather] No API key configured'); return; }
  const axios = (await import('axios')).default;

  for (const [locationId, venue] of Object.entries(VENUE_LOCATIONS)) {
    try {
      const r = await axios.get('https://api.openweathermap.org/data/2.5/weather', {
        params: { lat: venue.lat, lon: venue.lon, appid: apiKey, units: 'metric' }
      });
      const d = r.data;
      await database_js_1.db.query(
        "INSERT INTO weather_history (location_id, recorded_date, avg_temp_c, min_temp_c, max_temp_c, description, icon) " +
        "VALUES ($1, CURRENT_DATE, $2, $3, $4, $5, $6) " +
        "ON CONFLICT (location_id, recorded_date) DO UPDATE SET avg_temp_c=$2, min_temp_c=$3, max_temp_c=$4, description=$5, icon=$6",
        [locationId, d.main.temp, d.main.temp_min, d.main.temp_max, d.weather[0].description, d.weather[0].icon]
      );
      console.log('[Weather]', venue.name, d.main.temp + 'C', d.weather[0].description);
    } catch(e) { console.error('[Weather]', venue.name, e.message); }
  }
}

// Calendar context for a given week
router.get('/context/calendar', auth, async (req, res, next) => {
  try {
    const { date } = req.query;
    const baseDate = date ? new Date(date) : new Date();
    
    // Current week events
    const r = await database_js_1.db.query(
      "SELECT event_date, event_name, event_type, trade_impact FROM calendar_events " +
      "WHERE event_date >= DATE_TRUNC('week', $1::date) " +
      "AND event_date < DATE_TRUNC('week', $1::date) + INTERVAL '7 days' " +
      "ORDER BY event_date",
      [baseDate.toISOString().split('T')[0]]
    );

    // Same week last year events
    const lastYear = new Date(baseDate);
    lastYear.setFullYear(lastYear.getFullYear() - 1);
    const r2 = await database_js_1.db.query(
      "SELECT event_date, event_name, event_type, trade_impact FROM calendar_events " +
      "WHERE event_date >= DATE_TRUNC('week', $1::date) " +
      "AND event_date < DATE_TRUNC('week', $1::date) + INTERVAL '7 days' " +
      "ORDER BY event_date",
      [lastYear.toISOString().split('T')[0]]
    );

    // Weather this week vs last year
    const w1 = await database_js_1.db.query(
      "SELECT location_id, ROUND(AVG(avg_temp_c)::numeric,1) as avg_temp, MAX(description) as description, MAX(icon) as icon " +
      "FROM weather_history " +
      "WHERE recorded_date >= DATE_TRUNC('week', CURRENT_DATE) OR recorded_date = CURRENT_DATE " +
      "GROUP BY location_id"
    );
    const w2 = await database_js_1.db.query(
      "SELECT location_id, ROUND(AVG(avg_temp_c)::numeric,1) as avg_temp " +
      "FROM weather_history " +
      "WHERE recorded_date >= DATE_TRUNC('week', CURRENT_DATE - INTERVAL '1 year') " +
      "AND recorded_date < DATE_TRUNC('week', CURRENT_DATE - INTERVAL '1 year') + INTERVAL '7 days' " +
      "GROUP BY location_id"
    );

    // Build context message
    const thisWeekEvents = r.rows;
    const lastYearEvents = r2.rows;
    let contextMsg = '';
    
    if (thisWeekEvents.length > 0 && lastYearEvents.length === 0) {
      contextMsg = '📅 ' + thisWeekEvents.map(e => e.event_name).join(', ') + ' this week vs normal trading last year — expect higher footfall';
    } else if (thisWeekEvents.length === 0 && lastYearEvents.length > 0) {
      contextMsg = '📅 ' + lastYearEvents.map(e => e.event_name).join(', ') + ' last year vs normal trading this week — figures may be lower';
    } else if (thisWeekEvents.length > 0 && lastYearEvents.length > 0) {
      contextMsg = '📅 ' + thisWeekEvents.map(e => e.event_name).join(', ') + ' this year vs ' + lastYearEvents.map(e => e.event_name).join(', ') + ' last year';
    }

    ok(res, {
      thisWeek: thisWeekEvents,
      lastYear: lastYearEvents,
      weather: w1.rows,
      weatherLastYear: w2.rows,
      contextMessage: contextMsg,
    });
  } catch(e) { next(e); }
});

// Weather endpoint
router.get('/context/weather', auth, async (req, res, next) => {
  try {
    const r = await database_js_1.db.query(
      "SELECT w.location_id, w.recorded_date, w.avg_temp_c, w.description, w.icon, " +
      "ly.avg_temp_c as last_year_temp " +
      "FROM weather_history w " +
      "LEFT JOIN weather_history ly ON ly.location_id = w.location_id " +
      "AND ly.recorded_date = w.recorded_date - INTERVAL '1 year' " +
      "WHERE w.recorded_date >= CURRENT_DATE - INTERVAL '7 days' " +
      "ORDER BY w.location_id, w.recorded_date DESC"
    );
    ok(res, r.rows);
  } catch(e) { next(e); }
});

// Manual weather sync trigger
router.post('/sync/weather', auth, async (req, res, next) => {
  try {
    await syncWeather();
    ok(res, { message: 'Weather synced' });
  } catch(e) { next(e); }
});


// ── CPL LEARNING ─────────────────────────────────────────────────────────────

const CPL_KEY = process.env['CPL_API_KEY'];
const CPL_BASE = 'https://clientapi.cplonline.co.uk';

const CPL_SITES = {
  '0001': 153247,  // The Griffin Inn
  '0002': 162024,  // The Tap & Run  
  '0003': 171559,  // The Long Hop
};

async function syncCPL() {
  if (!CPL_KEY) { console.log('[CPL] No API key'); return; }
  const axios = (await import('axios')).default;
  const headers = { 'x-api-key': CPL_KEY };
  let totalSynced = 0;

  // Create CPL tables if not exist
  await database_js_1.db.query(`
    CREATE TABLE IF NOT EXISTS cpl_training (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      employee_id INTEGER,
      team_member_id UUID,
      location_id VARCHAR(10),
      course_id INTEGER,
      course_name VARCHAR(500),
      course_type INTEGER,
      status VARCHAR(50),
      score INTEGER,
      valid_from TIMESTAMPTZ,
      valid_to TIMESTAMPTZ,
      synced_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(employee_id, course_id)
    )
  `).catch(()=>{});

  await database_js_1.db.query(`
    CREATE TABLE IF NOT EXISTS cpl_users (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      employee_id INTEGER UNIQUE,
      employee_reference VARCHAR(50),
      first_name VARCHAR(100),
      last_name VARCHAR(100),
      site_id INTEGER,
      location_id VARCHAR(10),
      active BOOLEAN,
      email VARCHAR(255),
      team_member_id UUID,
      synced_at TIMESTAMPTZ DEFAULT NOW()
    )
  `).catch(()=>{});

  // Sync users across all sites
  for (const [locationId, siteId] of Object.entries(CPL_SITES)) {
    try {
      const usersR = await axios.get(CPL_BASE + '/users?siteId=' + siteId, { headers });
      const users = usersR.data || [];
      
      for (const u of users) {
        // Try to match to team_member by name
        const tmR = await database_js_1.db.query(
          "SELECT id FROM team_members WHERE location_id=$1 AND LOWER(first_name)=LOWER($2) AND LOWER(last_name)=LOWER($3) LIMIT 1",
          [locationId, u.firstname, u.lastname]
        ).catch(()=>({rows:[]}));
        const tmId = tmR.rows[0]?.id || null;

        // Map user's actual siteId to locationId
        const siteToLoc = {153247:'0001', 162024:'0002', 171559:'0003'};
        const userLocationId = siteToLoc[u.siteId] || locationId;
        await database_js_1.db.query(
          "INSERT INTO cpl_users (employee_id, employee_reference, first_name, last_name, site_id, location_id, active, email, team_member_id) " +
          "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) " +
          "ON CONFLICT (employee_id) DO UPDATE SET active=$7, email=$8, team_member_id=$9, location_id=$6, synced_at=NOW()",
          [u.employeeId, u.employeeReference||null, u.firstname, u.lastname, u.siteId, userLocationId, u.active, u.emailAddress||null, tmId]
        ).catch(()=>{});
      }
      console.log('[CPL] Users synced for', locationId, ':', users.length);

      // Sync training completions
      const trainR = await axios.get(CPL_BASE + '/users/training?siteId=' + siteId, { headers });
      const trainData = trainR.data || [];

      for (const t of trainData) {
        for (const course of t.training || []) {
          const statusVal = course.status?.find(s => s.type === 0)?.value || 'Unknown';
          const scoreVal = parseInt(course.status?.find(s => s.type === 1)?.value || '0');
          
          await database_js_1.db.query(
            "INSERT INTO cpl_training (employee_id, course_id, course_name, course_type, status, score, valid_from, valid_to) " +
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8) " +
            "ON CONFLICT (employee_id, course_id) DO UPDATE SET status=$5, score=$6, valid_from=$7, valid_to=$8, synced_at=NOW()",
            [t.employeeId, course.id, course.description?.replace(/\u001a/g,'').trim(), course.type,
             statusVal, scoreVal, course.validFrom||null, course.validTo||null]
          ).catch(()=>{});
          totalSynced++;
        }
      }
      console.log('[CPL] Training synced for', locationId, ':', trainData.length, 'staff');
    } catch(e) { console.error('[CPL] Error for', locationId, ':', e.message); }
  }
  return totalSynced;
}

// CPL sync endpoint
router.post('/sync/cpl', auth, async (req, res, next) => {
  try {
    const count = await syncCPL();
    ok(res, { message: 'CPL sync complete', records: count });
  } catch(e) { next(e); }
});

// CPL compliance overview
router.get('/cpl/compliance', auth, async (req, res, next) => {
  try {
    const { locationId } = req.query;
    const where = locationId ? "WHERE cu.location_id='" + locationId + "'" : '';
    const r = await database_js_1.db.query(
      "SELECT cu.first_name, cu.last_name, cu.location_id, cu.active, " +
      "COUNT(ct.course_id) as total_courses, " +
      "COUNT(ct.course_id) FILTER (WHERE ct.status='Complete') as completed, " +
      "COUNT(ct.course_id) FILTER (WHERE ct.valid_to < NOW()) as expired, " +
      "ROUND(AVG(ct.score)::numeric, 0) as avg_score " +
      "FROM cpl_users cu " +
      "LEFT JOIN cpl_training ct ON ct.employee_id = cu.employee_id " +
      where + " GROUP BY cu.first_name, cu.last_name, cu.location_id, cu.active " +
      "ORDER BY cu.location_id, completed DESC"
    ).catch(()=>({rows:[]}));
    ok(res, r.rows);
  } catch(e) { next(e); }
});

// CPL individual training record
router.get('/cpl/user/:employeeId', auth, async (req, res, next) => {
  try {
    const r = await database_js_1.db.query(
      "SELECT ct.*, cu.first_name, cu.last_name FROM cpl_training ct " +
      "JOIN cpl_users cu ON cu.employee_id = ct.employee_id " +
      "WHERE ct.employee_id=$1 ORDER BY ct.status DESC, ct.course_name",
      [req.params.employeeId]
    ).catch(()=>({rows:[]}));
    ok(res, r.rows);
  } catch(e) { next(e); }
});


// Team flex cost - using real RotaReady signed-off hours data
router.get('/metrics/team/flex', auth, async (req, res, next) => {
  try {
    const { locationId } = req.query;
    const locWhere = locationId ? "AND t.location_id='" + locationId + "'" : '';
    const axios = (await import('axios')).default;

    // This week's revenue
    // Use subquery to avoid row multiplication from sold_items join
    const salesR = await database_js_1.db.query(
      "SELECT t.location_id, " +
      "SUM(t.total_net_item_cost) as net_revenue, " +
      "(SELECT SUM(si.quantity) FROM relay_sold_items si JOIN relay_transactions t2 ON t2.id=si.transaction_id " +
      " WHERE t2.location_id=t.location_id AND si.sales_group='31' AND t2.datetime_opened >= DATE_TRUNC('week', NOW())) as covers " +
      "FROM relay_transactions t " +
      "WHERE t.datetime_opened >= DATE_TRUNC('week', NOW()) " + locWhere + " GROUP BY t.location_id"
    );

    // Get pay data from database (synced hourly by RotaReady sync)
    let payByEntity = {};
    try {
      const payR = await database_js_1.db.query(
        "SELECT location_id, " +
        "COUNT(DISTINCT user_id) as staff, " +
        "SUM(basic_pay) as basic, " +
        "SUM(total_pay) as total, " +
        "SUM(hours_paid) as hours " +
        "FROM rotaready_pay " +
        "WHERE pay_date >= DATE_TRUNC('week', CURRENT_DATE) " +
        "GROUP BY location_id"
      );
      payR.rows.forEach(r => {
        payByEntity[r.location_id] = {
          staff: Number(r.staff),
          basic: parseFloat(r.basic||0),
          total: parseFloat(r.total||0),
          hours: parseFloat(r.hours||0)
        };
      });
    } catch(e) { console.error('[Flex] Pay DB error:', e.message); }

    const result = salesR.rows.map(s => {
      const netRev = Number(s.net_revenue||0);
      const covers = Number(s.covers||0);
      const pay = payByEntity[s.location_id] || {basic:0, total:0, staff:0};
      const targetLabour = netRev * 0.28; // 28% labour cost target
      const actualLabour = pay.basic;
      const flex = targetLabour - actualLabour;
      return {
        location_id: s.location_id,
        net_revenue: netRev.toFixed(2),
        covers,
        staff_worked: pay.staff,
        hours_worked: pay.hours ? pay.hours.toFixed(1) : null,
        basic_pay: actualLabour.toFixed(2),
        total_cost: pay.total.toFixed(2),
        target_labour: targetLabour.toFixed(2),
        labour_pct: netRev > 0 ? ((actualLabour/netRev)*100).toFixed(1) : '0',
        flex: flex.toFixed(2),
        flex_direction: flex > 0 ? 'under' : 'over',
      };
    });
    ok(res, result);
  } catch(e) { next(e); }
});

// ─── SCORING ENGINE v3 - DB-driven ────────────────────────────────────────

// Metric definitions - maps DB metric_key to how we calculate the actual value
// actual_fn receives the raw clerk data and returns the actual value in target units
const METRIC_CALCULATORS = {
  avg_spend_dry: {
    label: 'ASPH (£)',
    actual: (m) => m.mains > 0 ? parseFloat((m.dry_rev / m.mains).toFixed(2)) : 0
  },
  sides_pct: {
    label: 'Sides % of Mains',
    actual: (m) => m.mains > 0 ? parseFloat((m.sides / m.mains * 100).toFixed(1)) : 0
  },
  nibbles_pct: {
    label: 'Nibbles % of Mains',
    actual: (m) => m.mains > 0 ? parseFloat((m.nibbles / m.mains * 100).toFixed(1)) : 0
  },
  starters_desserts: {
    label: 'Starters & Desserts % of Mains',
    actual: (m) => Number(m.mains) > 0 ? parseFloat(((Number(m.starters) + Number(m.desserts)) / Number(m.mains) * 100).toFixed(1)) : 0
  },
  drinks_per_cover: {
    label: 'Drinks % of Mains',
    actual: (m) => {
      if (m.mains < 1) return 0;
      const ratio = m.drinks / m.mains;
      return ratio > 10 ? 0 : parseFloat((ratio * 100).toFixed(1));
    }
  },
  premium_wine: {
    label: 'Premium Wine % of Mains',
    actual: (m) => m.mains > 0 ? parseFloat((m.prem_wine / m.mains * 100).toFixed(1)) : 0
  },
  avg_wine_spend: {
    label: 'Avg Wine Spend per Item',
    actual: (m) => m.all_wine > 0 ? parseFloat((Number(m.wine_net_rev) / Number(m.all_wine)).toFixed(2)) : 0
  },
  named_review: {
    label: 'Named Reviews',
    actual: (m) => Number(m.named_review || 0)
  },
  double_spirits: {
    label: 'Double Spirits % of Mains',
    actual: (m) => m.mains > 0 ? parseFloat((m.dbl_spirits / m.mains * 100).toFixed(1)) : 0
  },
  large_wine: {
    label: 'Large Wine % of Mains',
    actual: (m) => m.mains > 0 ? parseFloat((m.lg_wine / m.mains * 100).toFixed(1)) : 0
  },
  bottled_water: {
    label: 'Bottled Water % of Mains',
    actual: (m) => m.mains > 0 ? parseFloat((m.water / m.mains * 100).toFixed(1)) : 0
  },
  wine_per_10_mains: {
    label: 'Wine Items per 10 Mains',
    actual: (m) => m.mains > 0 ? parseFloat((Number(m.all_wine) / Number(m.mains) * 10).toFixed(1)) : 0
  },
  rev_per_labour_hour: {
    label: 'Revenue per Labour Hour (£)',
    actual: (m) => Number(m.est_hours) > 0 ? parseFloat((Number(m.dry_rev) / Number(m.est_hours)).toFixed(2)) : 0
  },
  avg_spend_wet: {
    label: 'Wet ASPH (£)',
    actual: (m) => m.mains > 0 ? parseFloat((m.wet_rev / m.mains).toFixed(2)) : 0
  },
};

function scoreMetric(actual, target) {
  if (!target || target === 0) return 50; // No target = neutral
  if (actual === 0) return 0;
  const ratio = actual / target;
  if (ratio >= 1) {
    // Above target: 50 + up to 50 bonus (capped at 100)
    // At 2x target = 100, at 1.5x target = 75
    return Math.min(100, Math.round(50 + (ratio - 1) * 100));
  } else {
    // Below target: linear from 0 to 50
    return Math.max(0, Math.round(ratio * 50));
  }
}

function calcFinalScore(metricScores, activeMetrics) {
  let totalWeight = 0;
  let weighted = 0;
  for (const m of activeMetrics) {
    const score = metricScores[m.metric_key] || 0;
    weighted += score * Number(m.weight);
    totalWeight += Number(m.weight);
  }
  return totalWeight > 0 ? Math.round(weighted / totalWeight) : 0;
}

function getSellerTier(score) {
  if (score >= 75) return 'could-say';
  if (score >= 50) return 'should-say';
  if (score >= 25) return 'have-to';
  return 'review';
}

async function calculateScores(period, locationId) {
  let pc = "";
  let interval = '7 days';
  let periodRange = { start: null, end: null };
  if (period === 'last_week') {
    const now = new Date();
    const day = now.getUTCDay();
    const thisMondayOffset = day === 0 ? 6 : day - 1;
    const lastSunday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - thisMondayOffset - 1));
    const lastMonday = new Date(Date.UTC(lastSunday.getUTCFullYear(), lastSunday.getUTCMonth(), lastSunday.getUTCDate() - 6));
    periodRange.start = lastMonday.toISOString().slice(0,10);
    periodRange.end = lastSunday.toISOString().slice(0,10);
    pc = "AND t.datetime_opened >= '" + periodRange.start + "' AND t.datetime_opened < ('" + periodRange.end + "'::date + INTERVAL '1 day')";
    interval = '7 days';
  } else {
    interval = period === 'month' ? '30 days' : period === 'today' ? '1 day' : '7 days';
    pc = "AND t.datetime_opened >= NOW() - INTERVAL '" + interval + "'";
  }

  // Load active metrics from DB - this is the single source of truth
  const metricsR = await database_js_1.db.query(
    "SELECT metric_key, name, weight, target, is_active FROM selector_metrics WHERE is_active=true ORDER BY weight DESC"
  );
  const activeMetrics = metricsR.rows;
  if (!activeMetrics.length) return [];

  const clerksR = await database_js_1.db.query(
    "SELECT DISTINCT rcm.clerk_id, rcm.location_id, rcm.team_member_id, " +
    "tm.display_name, tm.first_name, tm.last_name, v.name as venue_name, v.id as venue_id, " +
    "tm.avatar_initials, tm.avatar_color " +
    "FROM relay_clerk_mappings rcm " +
    "JOIN team_members tm ON tm.id=rcm.team_member_id " +
    "JOIN connector_venue_mappings cvm ON cvm.location_id=rcm.location_id " +
    "JOIN venues v ON v.id=cvm.venue_id " +
    "WHERE rcm.team_member_id IS NOT NULL AND tm.is_active = true AND tm.selector_excluded = false" +
    (locationId ? " AND rcm.location_id='" + locationId + "'" : "")
  );

  const scores = [];
  for (const clerk of clerksR.rows) {
    // Labour hours (rolling matching interval, estimated from rotaready_pay)
    const hoursR = await database_js_1.db.query(
      "SELECT COALESCE(SUM(CASE " +
      "  WHEN rp.hourly_rate > 5 AND NOT rp.is_salaried THEN rp.basic_pay / rp.hourly_rate " +
      "  WHEN rp.is_salaried AND rp.total_pay > 0 THEN rp.total_pay / 12.21 " +
      "  ELSE 0 END), 0) AS est_hours " +
      "FROM rotaready_pay rp " +
      "JOIN team_members tm ON tm.rota_id = rp.user_id::text " +
      "WHERE tm.id = $1 AND " + (period === 'last_week' ? "rp.pay_date BETWEEN '" + periodRange.start + "' AND '" + periodRange.end + "'" : "rp.pay_date >= now()::date - INTERVAL '" + interval + "'"),
      [clerk.team_member_id]
    ).catch(() => ({rows: [{est_hours: 0}]}));
    const estHours = Number(hoursR.rows[0]?.est_hours || 0);

    const mR = await database_js_1.db.query(
      "SELECT " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='31' AND si.individual_net_price>=5),0) as mains, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='32'),0) as sides, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='29'),0) as nibbles, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group='30'),0) as starters, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('33','35')),0) as desserts, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('1','2','3','4','5','6','8','9','10','15','17','18','19','21','22','23','26','27','28','38')),0) as drinks, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('3','4','5','6') AND (si.individual_net_price>40 OR (LOWER(si.name) LIKE 'btl%' AND si.individual_net_price>25))),0) as prem_wine, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('8','15')),0) as spirits, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('8','9','10') AND LOWER(si.name) LIKE '%dbl%'),0) as dbl_spirits, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('3','4','5','6') AND LOWER(si.name) LIKE '%250ml%'),0) as lg_wine, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE si.sales_group IN ('3','4','5','6')),0) as all_wine, " +
      "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('3','4','5','6')),0) as wine_net_rev, " +
      "COALESCE(SUM(si.quantity) FILTER (WHERE LOWER(si.name) LIKE '%water%' AND si.sales_group NOT IN ('30000','20')),0) as water, " +
      "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('1','2','3','4','5','6','8','9','10','15','17','18','19','21','22','23','26','27','28','38')),0) as wet_rev, " +
      "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('29','30','31','32','33','34','35') AND si.individual_net_price>0),0) as dry_rev, " +
      "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('29','30','31','32','33','34','35') AND si.individual_net_price>=0),0) as food_rev " +
      "FROM relay_transactions t " +
      "JOIN relay_sold_items si ON si.transaction_id=t.id " +
      "WHERE si.added_by_clerk_id=$1 AND t.location_id=$2 " + pc,
      [clerk.clerk_id, clerk.location_id]
    );

    const m = mR.rows[0];
    m.est_hours = estHours;
    const mains = Number(m.mains);
    if (mains < 20) continue; // Need 20+ mains for meaningful score

    // Count named reviews for this clerk
    const revR = await database_js_1.db.query(
      "SELECT COUNT(*) as cnt FROM google_reviews WHERE named_staff ILIKE '%' || $1 || '%' " +
      "AND review_date >= NOW() - INTERVAL '" + interval + "'",
      [clerk.first_name]
    ).catch(() => ({rows:[{cnt:0}]}));
    m.named_review = Number(revR.rows[0].cnt);

    // Calculate actuals for each active metric using calculator functions
    const actuals = {};
    const metricScores = {};

    for (const metric of activeMetrics) {
      const calc = METRIC_CALCULATORS[metric.metric_key];
      if (!calc) continue;
      const actual = calc.actual(m);
      actuals[metric.metric_key] = actual;
      metricScores[metric.metric_key] = scoreMetric(actual, Number(metric.target));
    }

    const finalScore = calcFinalScore(metricScores, activeMetrics);
    const tier = getSellerTier(finalScore);

    // Read previous cached score BEFORE we overwrite it
    const cachedR = await database_js_1.db.query(
      "SELECT selector_score FROM team_members WHERE id=$1",
      [clerk.team_member_id]
    ).catch(() => ({rows: []}));
    const cachedPriorScore = cachedR.rows[0]?.selector_score;

    // Update team_members table
    await database_js_1.db.query(
      "UPDATE team_members SET selector_score=$1, selector_tier=$2, selector_updated_at=NOW() WHERE id=$3",
      [finalScore, tier, clerk.team_member_id]
    ).catch(()=>{});

    // ---- Write weekly history snapshot ----
    const weekEnding = (() => {
      const d = new Date();
      const day = d.getDay();
      const daysToSun = day === 0 ? 0 : 7 - day;
      d.setDate(d.getDate() + daysToSun);
      return d.toISOString().slice(0, 10);
    })();
    const priorR = await database_js_1.db.query(
      "SELECT total_score FROM selector_scores WHERE team_member_id=$1 AND week_ending < $2 ORDER BY week_ending DESC LIMIT 1",
      [clerk.team_member_id, weekEnding]
    ).catch(() => ({rows: []}));
    let previousScore = priorR.rows[0]?.total_score ? Number(priorR.rows[0].total_score) : null;
    if (previousScore === null && cachedPriorScore !== null && cachedPriorScore !== undefined) {
      previousScore = Number(cachedPriorScore);
    }
    const scoreChange = previousScore !== null ? Number((finalScore - previousScore).toFixed(2)) : null;
    await database_js_1.db.query(
      "INSERT INTO selector_scores (team_member_id, venue_id, week_ending, total_score, previous_score, score_change, tier, programme_status, score_breakdown) " +
      "VALUES ($1,$2,$3,$4,$5,$6,$7,'on-programme',$8::jsonb) " +
      "ON CONFLICT (team_member_id, week_ending) DO UPDATE " +
      "SET total_score=EXCLUDED.total_score, previous_score=EXCLUDED.previous_score, score_change=EXCLUDED.score_change, tier=EXCLUDED.tier, score_breakdown=EXCLUDED.score_breakdown",
      [clerk.team_member_id, clerk.venue_id, weekEnding, finalScore, previousScore, scoreChange, tier,
       JSON.stringify({actuals, metric_scores: metricScores})]
    ).catch(e => console.error('[selector_scores] write failed:', e.message));

    scores.push({
      team_member_id: clerk.team_member_id,
      clerk_id: clerk.clerk_id,
      display_name: clerk.display_name,
      venue_name: clerk.venue_name,
      avatar_initials: clerk.avatar_initials,
      avatar_color: clerk.avatar_color,
      score: finalScore,
      tier,
      mains,
      actuals,
      metric_scores: metricScores,
      previous_score: previousScore,
      score_change: scoreChange,
      active_metrics: activeMetrics.map(m => ({key: m.metric_key, label: m.name, weight: m.weight, target: m.target}))
    });
  }

  return scores.sort((a,b) => b.score - a.score);
}


// Scores - calculate
router.post('/scores/calculate', auth, async (req, res, next) => {
  try {
    const { period, locationId, venue } = req.body || {};
    const locMap = {'griffin':'0001','taprun':'0002','longhop':'0003'};
    const loc = locationId || locMap[venue] || null;
    const scores = await calculateScores(period || 'week', loc);
    const top10 = scores.slice(0, 10);
    ok(res, { calculated: scores.length, top10, all: scores });
  } catch(e) { next(e); }
});

// Scores - leaderboard (read cached scores from team_members)
router.get('/scores/leaderboard', auth, async (req, res, next) => {
  try {
    const { period, venue, locationId } = req.query;
    const locMap = {'griffin':'0001','taprun':'0002','longhop':'0003'};
    const loc = locationId || locMap[venue] || null;
    
    // Recalculate fresh scores
    const scores = await calculateScores(period || 'week', loc);
    ok(res, scores);
  } catch(e) { next(e); }
});

// Individual score (rich detail for side panel)
router.get('/scores/:teamMemberId', auth, async (req, res, next) => {
  try {
    const tmId = req.params.teamMemberId;
    // 1. Team member basics
    const tmR = await database_js_1.db.query(
      'SELECT tm.id, tm.display_name, tm.first_name, tm.last_name, tm.avatar_initials, tm.avatar_color, tm.role, tm.department, tm.selector_score, tm.selector_tier, v.name as venue_name, v.id as venue_id ' +
      'FROM team_members tm JOIN venues v ON v.id=tm.venue_id WHERE tm.id=$1',
      [tmId]
    );
    if (!tmR.rows.length) return ok(res, null);
    const tm = tmR.rows[0];

    // 2. Weekly history (most recent first)
    const histR = await database_js_1.db.query(
      'SELECT week_ending, total_score, previous_score, score_change, tier, score_breakdown ' +
      'FROM selector_scores WHERE team_member_id=$1 ORDER BY week_ending DESC LIMIT 52',
      [tmId]
    ).catch(() => ({rows: []}));
    const history = histR.rows.map(h => ({
      week_ending: h.week_ending,
      total_score: Number(h.total_score),
      previous_score: h.previous_score !== null ? Number(h.previous_score) : null,
      score_change: h.score_change !== null ? Number(h.score_change) : null,
      tier: h.tier,
      actuals: h.score_breakdown?.actuals || null
    }));

    // 3. Rank in venue + venue total (from the latest week)
    const latestWeek = history[0]?.week_ending;
    let rankInVenue = null, venueTotal = null;
    if (latestWeek) {
      const rankR = await database_js_1.db.query(
        'SELECT team_member_id, total_score, ' +
        'RANK() OVER (ORDER BY total_score DESC) as rank, ' +
        'COUNT(*) OVER () as total ' +
        'FROM selector_scores WHERE venue_id=$1 AND week_ending=$2',
        [tm.venue_id, latestWeek]
      ).catch(() => ({rows: []}));
      const me = rankR.rows.find(r => r.team_member_id === tmId);
      if (me) { rankInVenue = Number(me.rank); venueTotal = Number(me.total); }
    }

    // 4. Per-metric deltas (current actual vs previous week's actual)
    const metricDeltas = {};
    if (history.length >= 2 && history[0].actuals && history[1].actuals) {
      const cur = history[0].actuals, prev = history[1].actuals;
      for (const k of Object.keys(cur)) {
        if (typeof cur[k] === 'number' && typeof prev[k] === 'number') {
          metricDeltas[k] = Number((cur[k] - prev[k]).toFixed(2));
        }
      }
    }

    // 5. Active metrics (for labels/targets)
    const metricsR = await database_js_1.db.query(
      'SELECT metric_key, name, target, weight, direction FROM selector_metrics WHERE is_active=true ORDER BY weight DESC'
    ).catch(() => ({rows: []}));

    ok(res, {
      team_member: {
        id: tm.id,
        name: tm.display_name,
        role: tm.role || null,
        department: tm.department || null,
        venue_name: tm.venue_name,
        avatar_initials: tm.avatar_initials,
        avatar_color: tm.avatar_color
      },
      current: {
        score: history[0]?.total_score ?? (tm.selector_score !== null ? Number(tm.selector_score) : null),
        tier: history[0]?.tier ?? tm.selector_tier,
        previous_score: history[0]?.previous_score ?? null,
        score_change: history[0]?.score_change ?? null,
        rank_in_venue: rankInVenue,
        venue_total: venueTotal,
        actuals: history[0]?.actuals || {},
        metric_deltas: metricDeltas
      },
      history,
      active_metrics: metricsR.rows.map(m => ({key: m.metric_key, label: m.name, target: Number(m.target), weight: m.weight, direction: m.direction}))
    });
  } catch(e) { next(e); }
});

// ── USER MANAGEMENT ──

// Seed default users if none exist
async function seedUsers() {
  const count = await database_js_1.db.query('SELECT COUNT(*) FROM coach_users');
  if (parseInt(count.rows[0].count) > 0) return;
  const users = [
    { email:'ian@foxitc.com', pass:'FoxITC2026!', name:'Ian Mackness', initials:'IM', role:'admin', venue:'all' },
    { email:'jack@foxitc.com', pass:'FoxITC2026!', name:'Jack Whitehead', initials:'JW', role:'admin', venue:'all' },
    { email:'lee@catandwickets.com', pass:'CW2026!', name:'Lee Cash', initials:'LC', role:'admin', venue:'all' },
    { email:'coach.griffin@catandwickets.com', pass:'Coach2026!', name:'Griffin Coach', initials:'GC', role:'gm', venue:'griffin' },
    { email:'coach.taprun@catandwickets.com', pass:'Coach2026!', name:'Tap & Run Coach', initials:'TC', role:'gm', venue:'taprun' },
    { email:'coach.longhop@catandwickets.com', pass:'Coach2026!', name:'Long Hop Coach', initials:'LH', role:'gm', venue:'longhop' },
  ];
  for (const u of users) {
    const bcrypt = require('bcrypt');
    const hash = await bcrypt.hash(u.pass, 10);
    await database_js_1.db.query(
      'INSERT INTO coach_users (email,password_hash,name,initials,role,venue) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (email) DO NOTHING',
      [u.email, hash, u.name, u.initials, u.role, u.venue]
    );
  }
  console.log('[Users] Default users seeded');
}
seedUsers().catch(e => console.error('[Users] Seed error:', e.message));

// Auth login via DB — queries platform_users (the real users table)
router.post('/auth/login/db', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const r = await database_js_1.db.query(
      "SELECT id, email, password_hash, first_name, last_name, role, venue_id, is_active " +
      "FROM platform_users WHERE lower(email)=lower($1) AND is_active=true", [email]
    );
    if (!r.rows.length) return err(res, 'Invalid credentials', 401);
    const user = r.rows[0];
    // platform_users uses bcryptjs-compatible hashes; require both to be safe
    let valid = false;
    try {
      const bcryptjs = require('bcryptjs');
      valid = await bcryptjs.compare(password, user.password_hash);
    } catch(e) {
      const bcrypt = require('bcrypt');
      valid = await bcrypt.compare(password, user.password_hash);
    }
    if (!valid) return err(res, 'Invalid credentials', 401);
    await database_js_1.db.query('UPDATE platform_users SET last_login=NOW() WHERE id=$1', [user.id]);
    // Build a UI-compatible user object (the frontend expects name/initials/venue fields)
    const fullName = [user.first_name, user.last_name].filter(Boolean).join(' ') || user.email;
    const initials = (user.first_name ? user.first_name[0] : user.email[0]).toUpperCase() +
                     (user.last_name  ? user.last_name[0]  : '').toUpperCase();
    // Map venue_id (UUID) back to a legacy venue slug the UI knows about
    const venueMap = {
      'e87b5986-0826-4464-ad62-e55175f9c3c4': 'griffin',
      '38749619-c192-45d1-806b-2fdc5922adea': 'taprun',
      'd9657ea0-19c4-4793-9c0c-21fd4179ac56': 'longhop'
    };
    const venueSlug = user.venue_id ? (venueMap[user.venue_id] || 'all') : 'all';
    const jwt = require('jsonwebtoken');
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role, venueId: user.venue_id },
      process.env.JWT_SECRET || 'selector-secret-2026',
      { expiresIn: '7d' }
    );
    ok(res, { token, user: {
      id: user.id,
      email: user.email,
      name: fullName,
      initials,
      role: user.role,
      venue: venueSlug
    }});
  } catch(e) { next(e); }
});

// ====================================================================
// USER ADMIN + CLERK MAPPING — platform_users era
// ====================================================================

// Helpers
function _isAdmin(req)   { return req.user && req.user.role === 'admin'; }
function _isHrOrAdmin(req) { return req.user && ['admin','hr'].includes(req.user.role); }
function _tempPw() {
  const { randomBytes } = require('crypto');
  return randomBytes(9).toString('base64').replace(/[+/=]/g,'').substring(0,12);
}

// List users — admin or hr
router.get('/users', auth, async (req, res, next) => {
  try {
    if (!_isHrOrAdmin(req)) return err(res, 'Forbidden', 403);
    const includeInactive = req.query.include_inactive === 'true';
    const where = includeInactive ? '' : 'WHERE is_active = true';
    const r = await database_js_1.db.query(
      "SELECT id, email, first_name, last_name, role, venue_id, is_active, " +
      "created_at, last_login FROM platform_users " + where +
      " ORDER BY is_active DESC, role, last_name NULLS LAST, email"
    );
    ok(res, r.rows);
  } catch(e) { next(e); }
});

// Create user — admin only (generates temp password, returned once)
router.post('/users', auth, async (req, res, next) => {
  try {
    if (!_isAdmin(req)) return err(res, 'Forbidden', 403);
    const { email, first_name, last_name, role, venue_id } = req.body;
    if (!email || !role) return err(res, 'email and role required', 400);
    if (!['admin','hr','coach','viewer'].includes(role)) return err(res, 'Invalid role', 400);
    const bcryptjs = require('bcryptjs');
    const pw = _tempPw();
    const hash = await bcryptjs.hash(pw, 10);
    const r = await database_js_1.db.query(
      "INSERT INTO platform_users (email, password_hash, first_name, last_name, role, venue_id, is_active) " +
      "VALUES ($1, $2, $3, $4, $5, $6, true) " +
      "RETURNING id, email, first_name, last_name, role, venue_id, is_active, created_at",
      [email.toLowerCase().trim(), hash, first_name||null, last_name||null, role, venue_id||null]
    );
    ok(res, { user: r.rows[0], temp_password: pw }, 201);
  } catch(e) {
    if (e.code === '23505') return err(res, 'Email already exists', 409);
    next(e);
  }
});

// Update user — admin only
router.put('/users/:id', auth, async (req, res, next) => {
  try {
    if (!_isAdmin(req)) return err(res, 'Forbidden', 403);
    const { id } = req.params;
    const { first_name, last_name, role, venue_id, is_active } = req.body;
    if (role && !['admin','hr','coach','viewer'].includes(role)) return err(res, 'Invalid role', 400);
    if (req.user.userId === id && (is_active === false || (role && role !== 'admin'))) {
      return err(res, "Can't deactivate yourself or remove your own admin role", 400);
    }
    const r = await database_js_1.db.query(
      "UPDATE platform_users SET " +
      "first_name = COALESCE($2, first_name), " +
      "last_name  = COALESCE($3, last_name), " +
      "role       = COALESCE($4, role), " +
      "venue_id   = COALESCE($5, venue_id), " +
      "is_active  = COALESCE($6, is_active), " +
      "updated_at = now() " +
      "WHERE id = $1 " +
      "RETURNING id, email, first_name, last_name, role, venue_id, is_active",
      [id, first_name, last_name, role, venue_id, typeof is_active === 'boolean' ? is_active : null]
    );
    if (!r.rows.length) return err(res, 'User not found', 404);
    ok(res, r.rows[0]);
  } catch(e) { next(e); }
});

// Reset password — admin only
router.post('/users/:id/reset-password', auth, async (req, res, next) => {
  try {
    if (!_isAdmin(req)) return err(res, 'Forbidden', 403);
    const bcryptjs = require('bcryptjs');
    const pw = _tempPw();
    const hash = await bcryptjs.hash(pw, 10);
    const r = await database_js_1.db.query(
      "UPDATE platform_users SET password_hash=$2, updated_at=now() WHERE id=$1 RETURNING email",
      [req.params.id, hash]
    );
    if (!r.rows.length) return err(res, 'User not found', 404);
    ok(res, { email: r.rows[0].email, temp_password: pw });
  } catch(e) { next(e); }
});

// Deactivate — admin only
router.delete('/users/:id', auth, async (req, res, next) => {
  try {
    if (!_isAdmin(req)) return err(res, 'Forbidden', 403);
    if (req.user.userId === req.params.id) return err(res, "Can't deactivate yourself", 400);
    const r = await database_js_1.db.query(
      "UPDATE platform_users SET is_active=false, updated_at=now() WHERE id=$1",
      [req.params.id]
    );
    if (!r.rowCount) return err(res, 'User not found', 404);
    ok(res, { deactivated: true });
  } catch(e) { next(e); }
});

// ====================================================================
// CLERK MAPPINGS — hr or admin
// ====================================================================

router.get('/clerk-mappings/stats', auth, async (req, res, next) => {
  try {
    if (!_isHrOrAdmin(req)) return err(res, 'Forbidden', 403);
    const r = await database_js_1.db.query(
      "SELECT COUNT(*)::int AS total, " +
      "COUNT(*) FILTER (WHERE team_member_id IS NOT NULL)::int AS mapped, " +
      "COUNT(*) FILTER (WHERE team_member_id IS NULL)::int AS unmapped " +
      "FROM relay_clerk_mappings"
    );
    ok(res, r.rows[0]);
  } catch(e) { next(e); }
});

router.get('/clerk-mappings/unmapped', auth, async (req, res, next) => {
  try {
    if (!_isHrOrAdmin(req)) return err(res, 'Forbidden', 403);
    const r = await database_js_1.db.query("SELECT * FROM v_unmapped_clerks");
    ok(res, r.rows);
  } catch(e) { next(e); }
});

router.get('/clerk-mappings/mapped', auth, async (req, res, next) => {
  try {
    if (!_isHrOrAdmin(req)) return err(res, 'Forbidden', 403);
    const r = await database_js_1.db.query("SELECT * FROM v_mapped_clerks");
    ok(res, r.rows);
  } catch(e) { next(e); }
});

router.get('/clerk-mappings/candidates', auth, async (req, res, next) => {
  try {
    if (!_isHrOrAdmin(req)) return err(res, 'Forbidden', 403);
    const { venue_id, q } = req.query;
    const conds = ['tm.is_active = true'];
    const params = [];
    if (venue_id) { params.push(venue_id); conds.push('tm.venue_id = $' + params.length); }
    if (q) {
      params.push('%' + q + '%');
      conds.push('(tm.display_name ILIKE $' + params.length +
                 ' OR tm.first_name ILIKE $' + params.length +
                 ' OR tm.last_name ILIKE $' + params.length + ')');
    }
    const r = await database_js_1.db.query(
      "SELECT tm.id, tm.display_name, tm.department, tm.role, tm.epos_id, v.name AS venue_name " +
      "FROM team_members tm LEFT JOIN venues v ON v.id = tm.venue_id " +
      "WHERE " + conds.join(' AND ') +
      " ORDER BY tm.display_name LIMIT 100",
      params
    );
    ok(res, r.rows);
  } catch(e) { next(e); }
});

router.post('/clerk-mappings/:clerk_id/map', auth, async (req, res, next) => {
  try {
    if (!_isHrOrAdmin(req)) return err(res, 'Forbidden', 403);
    const clerkId = parseInt(req.params.clerk_id, 10);
    const { team_member_id } = req.body;
    if (!team_member_id) return err(res, 'team_member_id required', 400);
    const r = await database_js_1.db.query(
      "UPDATE relay_clerk_mappings SET team_member_id=$2 WHERE clerk_id=$1 " +
      "RETURNING clerk_id, clerk_name, team_member_id",
      [clerkId, team_member_id]
    );
    if (!r.rows.length) return err(res, 'Clerk not found', 404);
    await database_js_1.db.query(
      "UPDATE team_members SET epos_id=$1::text, updated_at=now() " +
      "WHERE id=$2 AND (epos_id IS NULL OR epos_id='')",
      [clerkId, team_member_id]
    );
    ok(res, r.rows[0]);
  } catch(e) { next(e); }
});

router.post('/clerk-mappings/:clerk_id/unmap', auth, async (req, res, next) => {
  try {
    if (!_isHrOrAdmin(req)) return err(res, 'Forbidden', 403);
    const clerkId = parseInt(req.params.clerk_id, 10);
    const r = await database_js_1.db.query(
      "UPDATE relay_clerk_mappings SET team_member_id=NULL WHERE clerk_id=$1",
      [clerkId]
    );
    if (!r.rowCount) return err(res, 'Clerk not found', 404);
    ok(res, { unmapped: true });
  } catch(e) { next(e); }
});

// Toggle team member scoring inclusion (hr or admin)
router.put('/squad/:id/selector-toggle', auth, async (req, res, next) => {
  try {
    if (!req.user || !['admin','hr'].includes(req.user.role)) return err(res, 'Forbidden', 403);
    const { excluded } = req.body;
    if (typeof excluded !== 'boolean') return err(res, 'excluded (boolean) required', 400);
    const r = await database_js_1.db.query(
      "UPDATE team_members SET selector_excluded=$2, updated_at=NOW() WHERE id=$1 " +
      "RETURNING id, display_name, selector_excluded",
      [req.params.id, excluded]
    );
    if (!r.rows.length) return err(res, 'Team member not found', 404);
    ok(res, r.rows[0]);
  } catch(e) { next(e); }
});

// ── SYNC SCHEDULER ──────────────────────────────────────────────
async function runScheduledSyncs() {
  const now = new Date();
  const hour = now.getUTCHours();
  const min = now.getUTCMinutes();
  if (min >= 5) return; // Only run in first 5 mins of each hour

  console.log('[Scheduler] Tick at', now.toISOString());

  // TRAIL - 3x daily: 12:00, 17:00, 22:00 UTC
  if ([12, 17, 22].includes(hour)) {
    const label = hour===12?'post-morning':hour===17?'post-lunch':'evening close';
    console.log('[Scheduler] Trail sync -', label);
    try {
      const { createTrailConnector } = await import('../connectors/trail.js');
      const c = createTrailConnector();
      if (c) {
        const today = new Date();
        const day = today.getDay();
        const sun = new Date(today);
        sun.setDate(today.getDate() - (day===0?0:day));
        await c.syncAllVenues(sun.toISOString().split('T')[0]);
        console.log('[Scheduler] Trail complete -', label);
      }
    } catch(e) { console.error('[Scheduler] Trail error:', e.message); }
  }

  // GOOGLE REVIEWS - 3x daily: 09:00, 13:00, 21:00 UTC
  if ([9, 13, 21].includes(hour)) {
    const label = hour===9?'morning':hour===13?'post-lunch':'evening';
    console.log('[Scheduler] Google Reviews sync -', label);
    try {
      const tokenRow = await database_js_1.db.query('SELECT access_token FROM google_tokens LIMIT 1').catch(()=>({rows:[]}));
      if (tokenRow.rows.length) {
        const axios = (await import('axios')).default;
        const token = tokenRow.rows[0].access_token;
        const accounts = await axios.get('https://mybusinessaccountmanagement.googleapis.com/v1/accounts',
          {headers:{Authorization:'Bearer '+token}});
        console.log('[Scheduler] Google Reviews sync triggered -', label);
      } else {
        console.log('[Scheduler] Google not connected - skipping');
      }
    } catch(e) { console.error('[Scheduler] Google error:', e.message); }
  }

  // RESDIARY DATA EXTRACT - every 2 hours as backup to webhooks
  if (hour % 2 === 0) {
    console.log('[Scheduler] ResDiary Data Extract sync');
    try {
      const { createResDiaryConnector } = await import('../connectors/resdiary.js');
      const c = createResDiaryConnector();
      if (c) {
        const today = new Date().toISOString().split('T')[0];
        await c.syncAllVenues(today, today);
        console.log('[Scheduler] ResDiary complete');
      }
    } catch(e) { console.error('[Scheduler] ResDiary error:', e.message); }
  }

  // WEATHER - every 6 hours: 06:00, 12:00, 18:00, 00:00 UTC
  if ([0, 6, 12, 18].includes(hour)) {
    console.log('[Scheduler] Weather sync');
    try { await syncWeather(); } catch(e) { console.error('[Scheduler] Weather error:', e.message); }
  }

  // GOOGLE PLACES - hourly between 07:00-23:00 UTC
  if (hour >= 7 && hour <= 23) {
    console.log('[Scheduler] Google Places sync');
    try {
      const apiKey = process.env['GOOGLE_PLACES_API_KEY'];
      if (apiKey) {
        const axios = (await import('axios')).default;
        const venues = [
          {placeId:'ChIJkY6ikuPfeUgRTwYKwMOxnRQ', name:'The Griffin Inn', locationId:'0001'},
          {placeId:'ChIJL1fXX1rReUgRoasMv1zsgZI', name:'Tap & Run', locationId:'0002'},
          {placeId:'ChIJF_oJeAADekgRpSlCi0O92BI', name:'The Long Hop', locationId:'0003'},
        ];
        for (const venue of venues) {
          const r = await axios.get('https://maps.googleapis.com/maps/api/place/details/json', {
            params: {place_id: venue.placeId, fields: 'name,rating,user_ratings_total,reviews', key: apiKey, language: 'en'}
          });
          const place = r.data.result || {};
          await database_js_1.db.query(
            "INSERT INTO google_place_ratings (location_id, venue_name, rating, total_reviews, synced_at) VALUES ($1,$2,$3,$4,NOW()) " +
            "ON CONFLICT (location_id) DO UPDATE SET previous_rating=google_place_ratings.rating, previous_total=google_place_ratings.total_reviews, rating=$3, total_reviews=$4, synced_at=NOW()",
            [venue.locationId, venue.name, place.rating||0, place.user_ratings_total||0]
          ).catch(()=>{});
          console.log('[Scheduler] Google Places:', venue.name, place.rating, place.user_ratings_total);
        }
      }
    } catch(e) { console.error('[Scheduler] Google Places error:', e.message); }
  }

  // CPL - twice daily: 08:00 and 20:00 UTC
  if (hour === 8 || hour === 20) {
    console.log('[Scheduler] CPL daily sync');
    try { await syncCPL(); console.log('[Scheduler] CPL sync complete'); } catch(e) { console.error('[Scheduler] CPL error:', e.message); }
  }

  // ROTAREADY - hourly between 07:00-01:00 UTC (08:00-02:00 BST)
  const rrHour = hour;
  if (rrHour >= 6 || rrHour <= 1) {
    console.log('[Scheduler] RotaReady hourly sync');
    try {
      await syncRotaReadyStaff();
      console.log('[Scheduler] RotaReady sync complete');
    } catch(e) { console.error('[Scheduler] RotaReady error:', e.message); }
  }
}

// ROTAREADY 15-MIN SYNC - runs every 15 min, 24/7 for Harry's freshness
let _rrInProgress = false;
let _rrLastRun = 0;
async function runRotaready15min() {
  if (_rrInProgress) { console.log('[Scheduler] RR previous run in progress, skip'); return; }
  const now = Date.now();
  if ((now - _rrLastRun) < 14 * 60 * 1000) return;
  _rrInProgress = true;
  _rrLastRun = now;
  try {
    console.log('[Scheduler] RotaReady 15-min sync starting');
    await syncRotaReadyStaff();
    console.log('[Scheduler] RotaReady 15-min sync complete');
  } catch(e) {
    console.error('[Scheduler] RotaReady 15-min error:', e.message);
  } finally {
    _rrInProgress = false;
  }
}

// Wire up main scheduler - every 10 min
setInterval(runScheduledSyncs, 10 * 60 * 1000);
console.log('[Scheduler] Main scheduler wired - every 10 min');

// Wire up RotaReady 15-min scheduler
setInterval(runRotaready15min, 15 * 60 * 1000);
setTimeout(runRotaready15min, 30 * 1000);
console.log('[Scheduler] RotaReady 15-min scheduler wired');

// Force run on startup regardless of minute
async function runStartupSyncs() {
  console.log('[Scheduler] Running startup syncs...');
  try { await syncWeather(); } catch(e) { console.error('[Scheduler] Startup weather error:', e.message); }
  try {
    const axios = (await import('axios')).default;
    const apiKey = process.env['GOOGLE_PLACES_API_KEY'];
    if (apiKey) {
      const venues = [
        {placeId:'ChIJkY6ikuPfeUgRTwYKwMOxnRQ', name:'The Griffin Inn', locationId:'0001'},
        {placeId:'ChIJL1fXX1rReUgRoasMv1zsgZI', name:'Tap & Run', locationId:'0002'},
        {placeId:'ChIJF_oJeAADekgRpSlCi0O92BI', name:'The Long Hop', locationId:'0003'},
      ];
      for (const venue of venues) {
        const r = await axios.get('https://maps.googleapis.com/maps/api/place/details/json', {
          params: {place_id: venue.placeId, fields: 'name,rating,user_ratings_total,reviews', key: apiKey, language: 'en'}
        });
        const place = r.data.result || {};
        await database_js_1.db.query(
          "INSERT INTO google_place_ratings (location_id, venue_name, rating, total_reviews, synced_at) VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT (location_id) DO UPDATE SET previous_rating=google_place_ratings.rating, previous_total=google_place_ratings.total_reviews, rating=$3, total_reviews=$4, synced_at=NOW()",
          [venue.locationId, venue.name, place.rating||0, place.user_ratings_total||0]
        ).catch(()=>{});
        // Store reviews
        const reviews = place.reviews || [];
        for (const review of reviews) {
          const text = review.text || '';
          const reviewDate = new Date(review.time * 1000).toISOString();
          const membersRes = await database_js_1.db.query("SELECT first_name, last_name, venue_id FROM team_members WHERE is_active=true").catch(()=>({rows:[]}));
          const locVenueMap = {'0001':'e87b5986-0826-4464-ad62-e55175f9c3c4','0002':'38749619-c192-45d1-806b-2fdc5922adea','0003':'d9657ea0-19c4-4793-9c0c-21fd4179ac56'};
          const namedStaff = membersRes.rows.filter(m => m.venue_id === locVenueMap[venue.locationId] && text.toLowerCase().includes(m.first_name.toLowerCase()) && m.first_name.length > 2).map(m => m.first_name + ' ' + m.last_name);
          await database_js_1.db.query(
            "INSERT INTO google_reviews (location_name, reviewer_name, star_rating, comment, create_time, named_staff) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
            [venue.name, review.author_name, String(review.rating), text, reviewDate, namedStaff]
          ).catch(()=>{});
        }
        console.log('[Startup] Google Places:', venue.name, place.rating, place.user_ratings_total);
      }
    }
  } catch(e) { console.error('[Scheduler] Startup Google error:', e.message); }
  try { await syncRotaReadyStaff(); console.log('[Startup] RotaReady synced'); } catch(e) { console.error('[Startup] RotaReady error:', e.message); }
  try { await syncCPL(); console.log('[Startup] CPL synced'); } catch(e) { console.error('[Startup] CPL error:', e.message); }
  console.log('[Scheduler] Startup syncs complete');
}
setTimeout(runStartupSyncs, 10 * 1000);
