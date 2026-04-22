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

    // Upsert into resdiary_bookings
    if (booking && booking.Id) {
      const locMap = {'The Griffin Inn':'0001','The Tap & Run':'0002','The Long Hop':'0003'};
      const locationId = locMap[restaurantName] || null;
      const customerName = ((booking.Customer?.FirstName||'') + ' ' + (booking.Customer?.Surname||'')).trim();
      database_js_1.db.query(
        "INSERT INTO resdiary_bookings (booking_id, reference, restaurant_name, location_id, visit_date, visit_time, party_size, table_numbers, table_ids, area_ids, booking_status, arrival_status, meal_status, channel_code, customer_email, customer_name, special_requests, booking_duration, customer_spend, last_event_type, last_event_at) " +
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) " +
        "ON CONFLICT (booking_id) DO UPDATE SET booking_status=EXCLUDED.booking_status, arrival_status=EXCLUDED.arrival_status, meal_status=EXCLUDED.meal_status, table_numbers=EXCLUDED.table_numbers, party_size=EXCLUDED.party_size, last_event_type=EXCLUDED.last_event_type, last_event_at=EXCLUDED.last_event_at, updated_at=NOW()",
        [booking.Id, reference, restaurantName, locationId,
         visitDate||null, visitTime||null, partySize||0,
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
    upserted++;
  }
  // Sync pay/labour data
  try {
    const now = new Date();
    // Pull rolling 28 days to build history
    const startD = new Date(now);
    startD.setUTCDate(startD.getUTCDate() - 28);
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
          "INSERT INTO rotaready_pay (user_id, entity_id, location_id, pay_date, basic_pay, total_pay, hours_paid, hourly_rate, is_salaried) " +
          "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) " +
          "ON CONFLICT (user_id, pay_date, entity_id) DO UPDATE SET basic_pay=$5, total_pay=$6, hours_paid=$7, synced_at=NOW()",
          [item.userId, item.entityId, loc, item.date?.split('T')[0],
           parseFloat(cp.base||0), parseFloat(cp.totalPay||0),
           isSalaried ? 0 : parseFloat(w.durationPaid||0),
           isSalaried ? 0 : parseFloat(w.payAmount||0), isSalaried]
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
    const interval = period === 'month' ? '30 days' : period === 'today' ? '1 day' : '7 days';
    
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
    const { venue, date, status } = req.query;
    const locMap = {'griffin':'0001','taprun':'0002','longhop':'0003'};
    const conditions = ["restaurant_name NOT LIKE '%Test%'"];
    const params = [];
    if (venue && locMap[venue]) { params.push(locMap[venue]); conditions.push('location_id=$'+params.length); }
    if (date) { params.push(date); conditions.push('visit_date=$'+params.length); }
    if (status) { params.push(status); conditions.push('booking_status=$'+params.length); }
    const where = conditions.length ? 'WHERE '+conditions.join(' AND ') : '';
    const r = await database_js_1.db.query(
      'SELECT booking_id, reference, restaurant_name, location_id, visit_date, visit_time, party_size, table_numbers, booking_status, arrival_status, meal_status, customer_name, special_requests, channel_code, last_event_type, last_event_at ' +
      'FROM resdiary_bookings ' + where + ' ORDER BY visit_date ASC, visit_time ASC',
      params
    );
    ok(res, r.rows);
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
    label: 'Dry ASPH (£)',
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
    actual: (m) => m.mains > 0 ? parseFloat(((m.starters + m.desserts) / m.mains * 100).toFixed(1)) : 0
  },
  drinks_per_cover: {
    label: 'Drinks per Main',
    actual: (m) => m.mains > 0 ? parseFloat((m.drinks / m.mains).toFixed(2)) : 0
  },
  premium_wine: {
    label: 'Premium Wine per Cover',
    actual: (m) => m.mains > 0 ? parseFloat((m.prem_wine / m.mains).toFixed(2)) : 0
  },
  named_review: {
    label: 'Named Reviews',
    actual: (m) => Number(m.named_review || 0)
  },
  double_spirits: {
    label: 'Double Spirits %',
    actual: (m) => m.spirits > 0 ? parseFloat((m.dbl_spirits / m.spirits * 100).toFixed(1)) : 0
  },
  large_wine: {
    label: 'Large Wine %',
    actual: (m) => m.all_wine > 0 ? parseFloat((m.lg_wine / m.all_wine * 100).toFixed(1)) : 0
  },
  bottled_water: {
    label: 'Bottled Water per 10 Mains',
    actual: (m) => m.mains > 0 ? parseFloat((m.water / m.mains * 10).toFixed(1)) : 0
  },
  avg_spend_wet: {
    label: 'Wet ASPH (£)',
    actual: (m) => m.mains > 0 ? parseFloat((m.wet_rev / m.mains).toFixed(2)) : 0
  },
};

function scoreMetric(actual, target) {
  if (!target || target === 0) return 0;
  const ratio = actual / target;
  // Linear: 0 at zero actual, 100 at target, capped at 100
  return Math.min(100, Math.round(ratio * 100));
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
  const interval = period === 'month' ? '30 days' : period === 'today' ? '1 day' : '7 days';
  const pc = "AND t.datetime_opened >= NOW() - INTERVAL '" + interval + "'";

  // Load active metrics from DB - this is the single source of truth
  const metricsR = await database_js_1.db.query(
    "SELECT metric_key, name, weight, target, is_active FROM selector_metrics WHERE is_active=true ORDER BY weight DESC"
  );
  const activeMetrics = metricsR.rows;
  if (!activeMetrics.length) return [];

  const clerksR = await database_js_1.db.query(
    "SELECT DISTINCT rcm.clerk_id, rcm.location_id, rcm.team_member_id, " +
    "tm.display_name, tm.first_name, tm.last_name, v.name as venue_name, " +
    "tm.avatar_initials, tm.avatar_color " +
    "FROM relay_clerk_mappings rcm " +
    "JOIN team_members tm ON tm.id=rcm.team_member_id " +
    "JOIN connector_venue_mappings cvm ON cvm.location_id=rcm.location_id " +
    "JOIN venues v ON v.id=cvm.venue_id " +
    "WHERE rcm.team_member_id IS NOT NULL" +
    (locationId ? " AND rcm.location_id='" + locationId + "'" : "")
  );

  const scores = [];
  for (const clerk of clerksR.rows) {
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
      "COALESCE(SUM(si.quantity) FILTER (WHERE LOWER(si.name) LIKE '%water%' AND si.sales_group NOT IN ('30000','20')),0) as water, " +
      "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('1','2','3','4','5','6','8','9','10','15','17','18','19','21','22','23','26','27','28','38')),0) as wet_rev, " +
      "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group='31' AND si.individual_net_price>=5),0) as dry_rev, " +
      "COALESCE(SUM(si.total_net_price) FILTER (WHERE si.sales_group IN ('29','30','31','32','33','34','35') AND si.individual_net_price>=0),0) as food_rev " +
      "FROM relay_transactions t " +
      "JOIN relay_sold_items si ON si.transaction_id=t.id " +
      "WHERE si.added_by_clerk_id=$1 AND t.location_id=$2 " + pc,
      [clerk.clerk_id, clerk.location_id]
    );

    const m = mR.rows[0];
    const mains = Number(m.mains);
    if (mains < 5) continue;

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

    // Update team_members table
    await database_js_1.db.query(
      "UPDATE team_members SET selector_score=$1, selector_tier=$2, selector_updated_at=NOW() WHERE id=$3",
      [finalScore, tier, clerk.team_member_id]
    ).catch(()=>{});

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
      active_metrics: activeMetrics.map(m => ({key: m.metric_key, label: m.name, weight: m.weight, target: m.target}))
    });
  }

  return scores.sort((a,b) => b.score - a.score);
}

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

// Auth login via DB
router.post('/auth/login/db', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const r = await database_js_1.db.query(
      'SELECT * FROM coach_users WHERE email=$1 AND is_active=true', [email]
    );
    if (!r.rows.length) return err(res, 'Invalid credentials', 401);
    const user = r.rows[0];
    const bcrypt = require('bcrypt');
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return err(res, 'Invalid credentials', 401);
    await database_js_1.db.query('UPDATE coach_users SET last_login=NOW() WHERE id=$1', [user.id]);
    const jwt = require('jsonwebtoken');
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role, venueId: null },
      process.env.JWT_SECRET || 'selector-secret-2026',
      { expiresIn: '7d' }
    );
    ok(res, { token, user: { id: user.id, email: user.email, name: user.name, initials: user.initials, role: user.role, venue: user.venue } });
  } catch(e) { next(e); }
});

// Get all users (admin only)
router.get('/users', auth, async (req, res, next) => {
  try {
    if (!['admin'].includes(req.user?.role)) return err(res, 'Forbidden', 403);
    const r = await database_js_1.db.query(
      'SELECT id, email, name, initials, role, venue, is_active, created_at, last_login FROM coach_users ORDER BY created_at'
    );
    ok(res, r.rows);
  } catch(e) { next(e); }
});

// Create user (admin only)
router.post('/users', auth, async (req, res, next) => {
  try {
    if (!['admin'].includes(req.user?.role)) return err(res, 'Forbidden', 403);
    const { email, password, name, initials, role, venue } = req.body;
    if (!email || !password || !name) return err(res, 'email, password and name required', 400);
    const bcrypt = require('bcrypt');
    const hash = await bcrypt.hash(password, 10);
    const ini = initials || (name.split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2));
    const r = await database_js_1.db.query(
      'INSERT INTO coach_users (email,password_hash,name,initials,role,venue) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,email,name,initials,role,venue,is_active,created_at',
      [email.toLowerCase(), hash, name, ini, role||'coach', venue||'all']
    );
    ok(res, r.rows[0], 201);
  } catch(e) {
    if (e.code === '23505') return err(res, 'Email already exists', 409);
    next(e);
  }
});

// Update user (admin only)
router.put('/users/:id', auth, async (req, res, next) => {
  try {
    if (!['admin'].includes(req.user?.role)) return err(res, 'Forbidden', 403);
    const { id } = req.params;
    const { name, role, venue, is_active, password } = req.body;
    if (password) {
      const bcrypt = require('bcrypt');
    const hash = await bcrypt.hash(password, 10);
      await database_js_1.db.query(
        'UPDATE coach_users SET name=$1,role=$2,venue=$3,is_active=$4,password_hash=$5,updated_at=NOW() WHERE id=$6',
        [name, role, venue, is_active, hash, id]
      );
    } else {
      await database_js_1.db.query(
        'UPDATE coach_users SET name=$1,role=$2,venue=$3,is_active=$4,updated_at=NOW() WHERE id=$5',
        [name, role, venue, is_active, id]
      );
    }
    ok(res, { message: 'User updated' });
  } catch(e) { next(e); }
});

// Delete user (admin only)
router.delete('/users/:id', auth, async (req, res, next) => {
  try {
    if (!['admin'].includes(req.user?.role)) return err(res, 'Forbidden', 403);
    await database_js_1.db.query('UPDATE coach_users SET is_active=false WHERE id=$1', [req.params.id]);
    ok(res, { message: 'User deactivated' });
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

// Wire up scheduler - run every 10 minutes, function self-limits to first 5 mins of hour
setInterval(runScheduledSyncs, 10 * 60 * 1000);
// Startup syncs run immediately regardless of hour/minute
console.log('[Scheduler] Scheduler wired - running every 10 minutes');


// Wire up scheduler - run every 10 minutes, function self-limits to first 5 mins of hour
setInterval(runScheduledSyncs, 10 * 60 * 1000);
// Startup syncs run immediately regardless of hour/minute
console.log('[Scheduler] Scheduler wired - running every 10 minutes');

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
