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
        const venueId = req.query['venueId'] ?? user.venueId ?? undefined;
        const result = await database_js_1.db.query(`SELECT tm.*, v.name AS venue_name, v.short_name AS venue_short_name,
              ss.total_score, ss.tier, ss.programme_status, ss.score_change,
              ss.assessment_score, ss.epos_score, ss.operational_score,
              ss.coaching_narrative, ss.rank_in_venue
       FROM team_members tm
       JOIN venues v ON v.id = tm.venue_id
       LEFT JOIN selector_scores ss ON ss.team_member_id = tm.id AND ss.week_ending = $2
       WHERE tm.is_active = true
         AND ($1::uuid IS NULL OR tm.venue_id = $1)
       ORDER BY ss.rank_in_venue ASC NULLS LAST, tm.last_name, tm.first_name`, [venueId ?? null, weekStr()]);
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
    const areas = await database_js_1.db.query(
      'SELECT m.*, v.name AS venue_name FROM trail_venue_metrics m JOIN venues v ON v.id = m.venue_id WHERE m.week_ending = $1 ORDER BY v.name, m.area',
      [week]
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
      'SELECT t.id, t.location_id, t.business_date, t.datetime_opened, t.datetime_closed, t.covers, t.seating_area, t.total_gross_item_cost, t.closed_by_clerk_id, t.terminal_id, t.received_at FROM relay_transactions t ORDER BY t.received_at DESC LIMIT $1',
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
    const { period, locationId } = req.query;
    const locMap = {griffin:'0001', taprun:'0002', longhop:'0003'};
    const locId = locationId && locationId !== 'all' ? (locMap[locationId] || locationId) : null;
    const locWhere = locId ? " AND t.location_id = '" + locId + "'" : '';
    const result = await database_js_1.db.query(
      "SELECT COUNT(*) AS total_transactions," +
      " COALESCE(SUM(t.total_gross_item_cost),0) AS total_revenue," +
      " COALESCE(SUM(COALESCE(m.mains_count, 0)),0) AS total_covers," +
      " COALESCE(AVG(CASE WHEN COALESCE(m.mains_count,0)>0 THEN t.total_gross_item_cost::decimal/m.mains_count ELSE NULL END),0) AS avg_transaction," +
      " COALESCE(SUM(CASE WHEN DATE(t.datetime_opened)=CURRENT_DATE THEN 1 ELSE 0 END),0) AS today_transactions," +
      " COALESCE(SUM(CASE WHEN DATE(t.datetime_opened)=CURRENT_DATE THEN t.total_gross_item_cost ELSE 0 END),0) AS today_revenue," +
      " COALESCE(SUM(CASE WHEN t.datetime_opened >= NOW() - (7 * INTERVAL '1 day') THEN 1 ELSE 0 END),0) AS week_transactions," +
      " COALESCE(SUM(CASE WHEN t.datetime_opened >= NOW() - (7 * INTERVAL '1 day') THEN t.total_gross_item_cost ELSE 0 END),0) AS week_revenue," +
      " COALESCE(SUM(CASE WHEN t.datetime_opened >= NOW() - (30 * INTERVAL '1 day') THEN 1 ELSE 0 END),0) AS month_transactions," +
      " COALESCE(SUM(CASE WHEN t.datetime_opened >= NOW() - (30 * INTERVAL '1 day') THEN t.total_gross_item_cost ELSE 0 END),0) AS month_revenue," +
      " COUNT(DISTINCT t.location_id) AS active_locations" +
      " FROM relay_transactions t" +
      " LEFT JOIN (SELECT transaction_id, SUM(quantity) AS mains_count FROM relay_sold_items WHERE sales_group='31' GROUP BY transaction_id) m ON m.transaction_id=t.id" +
      " WHERE 1=1" + locWhere
    ).catch(() => ({ rows: [{}] }));
    ok(res, result.rows[0]);
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
    const login = await axios.post('https://api.rdbranch.com/api/ConsumerApi/v1/login',
      { username: u, password: p }, { timeout: 15000 });
    const token = login.data?.Token || login.data?.token || login.data;
    const user = await axios.get('https://api.rdbranch.com/api/ConsumerApi/v1/CurrentUser',
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
    const areas = await database_js_1.db.query(
      'SELECT m.*, v.name AS venue_name FROM trail_venue_metrics m JOIN venues v ON v.id = m.venue_id WHERE m.week_ending = $1 ORDER BY v.name, m.area',
      [week]
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
      "ON CONFLICT (rota_id) DO UPDATE SET first_name=EXCLUDED.first_name, last_name=EXCLUDED.last_name, " +
      "display_name=EXCLUDED.display_name, venue_id=EXCLUDED.venue_id, is_active=EXCLUDED.is_active, updated_at=NOW()",
      [venueId, s.firstName, s.lastName, s.firstName+' '+s.lastName, initials, String(s.id), s.flags.active]
    ).catch(e => console.error('[RotaReady] Upsert error:', e.message));
    upserted++;
  }
  console.log('[RotaReady] Staff sync complete:', upserted, 'staff processed');
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
    status.resdiary = {status:'pending', webhookEvents: rsdR.rows[0]?.total, lastSync: rsdR.rows[0]?.last_received};
    const rrOk = !!(env.ROTAREADY_REALM_ID && env.ROTAREADY_CONSUMER_KEY && env.ROTAREADY_CONSUMER_SECRET);
    const rrR = await database_js_1.db.query("SELECT COUNT(*) as total, MAX(updated_at) as last_sync FROM team_members WHERE rota_id IS NOT NULL").catch(()=>({rows:[{}]}));
    status.rotaready = {status: rrOk && Number(rrR.rows[0]?.total)>0?'connected':rrOk?'configured':'offline', lastSync: rrR.rows[0]?.last_sync, staffCount: rrR.rows[0]?.total};
    const gR = await database_js_1.db.query("SELECT COUNT(*) as total FROM google_tokens").catch(()=>({rows:[{total:0}]}));
    status.google = {status: Number(gR.rows[0]?.total)>0?'connected':'offline'};
    status.cpl = {status: env.CPL_API_KEY?'configured':'offline', note:'Demo account'};
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
      "SELECT * FROM google_place_ratings ORDER BY location_id"
    ).catch(() => ({ rows: [] }));
    const reviews = await database_js_1.db.query(
      "SELECT location_name, reviewer_name, star_rating, comment, create_time, named_staff " +
      "FROM google_reviews ORDER BY create_time DESC LIMIT 50"
    ).catch(() => ({ rows: [] }));
    ok(res, { ratings: ratings.rows, reviews: reviews.rows });
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
            "INSERT INTO google_place_ratings (location_id, venue_name, rating, total_reviews, synced_at) VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT (location_id) DO UPDATE SET rating=$3, total_reviews=$4, synced_at=NOW()",
            [venue.locationId, venue.name, place.rating||0, place.user_ratings_total||0]
          ).catch(()=>{});
          console.log('[Scheduler] Google Places:', venue.name, place.rating, place.user_ratings_total);
        }
      }
    } catch(e) { console.error('[Scheduler] Google Places error:', e.message); }
  }

  // CPL - daily at 08:00 UTC
  if (hour === 8) {
    console.log('[Scheduler] CPL daily sync');
    // CPL connector to be built once real account is set up
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