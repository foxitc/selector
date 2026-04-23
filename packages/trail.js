"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TrailConnector = void 0;
exports.createTrailConnector = createTrailConnector;
// @ts-nocheck
const axios_1 = __importDefault(require("axios"));
const database_js_1 = require("../config/database.js");
const crypto_1 = require("crypto");
const BASE_URL = 'https://web.trailapp.com/api/public';
class TrailConnector {
    constructor(apiKey) {
        this.apiKey = apiKey;
        this.client = axios_1.default.create({
            baseURL: BASE_URL,
            timeout: 30000,
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'API_KEY': apiKey },
        });
    }
    async testConnection() {
        try {
            const response = await this.client.get('/areas/v1/list');
            const areas = (response.data.data ?? []).map(a => a.name);
            return { success: true, message: `Connected — ${areas.length} areas accessible`, areas };
        }
        catch (err) {
            return { success: false, message: err.message, areas: [] };
        }
    }
    async fetchTaskInstances(startDate, endDate) {
        const all = [];
        let cursor = null;
        do {
            const body = { startDate, endDate };
            if (cursor)
                body.pageStart = cursor;
            const response = await this.client.post('/task_reports/v1/task_instances', body);
            all.push(...(response.data.data ?? []));
            cursor = response.data.page?.nextCursor ?? null;
            if (cursor)
                await new Promise(r => setTimeout(r, 1100));
        } while (cursor);
        return all;
    }
    async syncAllVenues(weekEnding) {
        const weekEnd = new Date(weekEnding);
        const weekStart = new Date(weekEnd);
        weekStart.setDate(weekEnd.getDate() - 6);
        const startDate = weekStart.toISOString().split('T')[0];
        console.log(`[Trail] Syncing week ${startDate} to ${weekEnding}`);
        const allTasks = await this.fetchTaskInstances(startDate, weekEnding);
        console.log(`[Trail] ${allTasks.length} task instances fetched`);
        const bySite = new Map();
        for (const task of allTasks) {
            const existing = bySite.get(task.siteId) ?? [];
            existing.push(task);
            bySite.set(task.siteId, existing);
        }
        const venues = (await database_js_1.db.query('SELECT id, name, short_name FROM venues WHERE is_active = true')).rows;
        await database_js_1.db.query(`CREATE TABLE IF NOT EXISTS trail_venue_metrics (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      venue_id UUID NOT NULL REFERENCES venues(id),
      trail_site_id INTEGER NOT NULL,
      trail_site_name VARCHAR(255),
      week_ending DATE NOT NULL,
      area VARCHAR(10) DEFAULT 'ALL',
      total_tasks INTEGER DEFAULT 0,
      completed_tasks INTEGER DEFAULT 0,
      not_completed_tasks INTEGER DEFAULT 0,
      completion_rate NUMERIC(5,2) DEFAULT 0,
      completed_early INTEGER DEFAULT 0,
      completed_on_time INTEGER DEFAULT 0,
      completed_late INTEGER DEFAULT 0,
      total_exceptions INTEGER DEFAULT 0,
      total_flagged INTEGER DEFAULT 0,
      exception_rate NUMERIC(6,3) DEFAULT 0,
      trail_score NUMERIC(5,2) DEFAULT 0,
      synced_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (venue_id, week_ending, area)
    )`);
        for (const [siteId, tasks] of bySite) {
            const siteName = tasks[0].siteName;
            const area = siteName.toLowerCase().includes('boh') ? 'BOH' : 'FOH';
            const vWords = siteName.toLowerCase().replace('the ', '').split(' ');
            const venue = venues.find(v => {
                const sLower = v.name.toLowerCase().replace('the ', '').split(' ');
                return sLower.some(w => w.length > 2 && vWords.includes(w));
            });
            if (!venue) {
                console.warn(`[Trail] No match for "${siteName}"`);
                continue;
            }
            // Trail uses different status strings for BOH vs FOH
            const COMPLETED_STATUSES = ['completedEarly', 'completedOnTime', 'completedLate', 'completed'];
            const NOT_COMPLETED_STATUSES = ['notCompleted', 'missed'];
            const completed = tasks.filter(t => COMPLETED_STATUSES.includes(t.status));
            const notCompleted = tasks.filter(t => NOT_COMPLETED_STATUSES.includes(t.status));
            const early = tasks.filter(t => t.status === 'completedEarly');
            const onTime = tasks.filter(t => ['completedOnTime', 'completed'].includes(t.status));
            const late = tasks.filter(t => t.status === 'completedLate');
            const total = tasks.length;
            const completionRate = total > 0 ? Math.round((completed.length / total) * 10000) / 100 : 0;
            const totalExceptions = tasks.reduce((s, t) => s + (t.exceptionCount ?? 0), 0);
            const totalFlagged = tasks.reduce((s, t) => s + (t.flaggedChecklistCount ?? 0), 0);
            const exceptionRate = completed.length > 0 ? Math.round((totalExceptions / completed.length) * 100) / 100 : 0;
            const timingBonus = completed.length > 0 ? ((early.length * 1.0 + onTime.length * 0.8 + late.length * 0.4) / completed.length) * 100 : 0;
            const trailScore = Math.max(0, Math.min(100, Math.round(((completionRate * 0.70) + (timingBonus * 0.20) - Math.min(exceptionRate * 10, 20)) * 100) / 100));
            await database_js_1.db.query(`INSERT INTO trail_venue_metrics (id,venue_id,trail_site_id,trail_site_name,week_ending,area,total_tasks,completed_tasks,not_completed_tasks,completion_rate,completed_early,completed_on_time,completed_late,total_exceptions,total_flagged,exception_rate,trail_score)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
         ON CONFLICT (venue_id, week_ending, area) DO UPDATE SET
         total_tasks=EXCLUDED.total_tasks, completed_tasks=EXCLUDED.completed_tasks,
         not_completed_tasks=EXCLUDED.not_completed_tasks, completion_rate=EXCLUDED.completion_rate,
         completed_early=EXCLUDED.completed_early, completed_on_time=EXCLUDED.completed_on_time,
         completed_late=EXCLUDED.completed_late, total_exceptions=EXCLUDED.total_exceptions,
         total_flagged=EXCLUDED.total_flagged, exception_rate=EXCLUDED.exception_rate,
         trail_score=EXCLUDED.trail_score, synced_at=NOW()`, [(0, crypto_1.randomUUID)(), venue.id, siteId, siteName, weekEnding, area, total, completed.length,
                notCompleted.length, completionRate, early.length, onTime.length, late.length,
                totalExceptions, totalFlagged, exceptionRate, trailScore]);
            console.log(`[Trail] ✓ ${siteName} — ${completionRate}% complete, score: ${trailScore}`);
        }
    }
}
exports.TrailConnector = TrailConnector;
function createTrailConnector() {
    const apiKey = process.env.TRAIL_API_KEY;
    if (!apiKey) {
        console.warn('[Trail] TRAIL_API_KEY not set');
        return null;
    }
    return new TrailConnector(apiKey);
}
