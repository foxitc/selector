// ================================================================
// THE CLUB — Trail Connector
// Pulls task completion rates and compliance scores per venue.
// Uses API_KEY header auth (key stored in TRAIL_API_KEY env var).
// Data refreshed twice daily by Trail — we sync weekly.
// ================================================================

import axios, { type AxiosInstance, type AxiosError } from 'axios';
import { db } from '../config/database.js';
import { randomUUID } from 'crypto';

const BASE_URL = 'https://web.trailapp.com/api/public';

// ----------------------------------------------------------------
// Trail API Types
// ----------------------------------------------------------------
interface TrailArea {
  id: number;
  name: string;
}

interface TrailTaskInstance {
  taskInstanceId: number;
  dueFromDatetime: string | null;
  dueByDatetime: string | null;
  completedDatetime: string | null;
  siteId: number;
  siteName: string;
  areaId: number | null;
  areaName: string | null;
  taskTemplateId: number;
  taskInstanceName: string;
  status: string;
  // completedEarly | completedOnTime | completedLate | notCompleted | inProgress | notStarted
  exceptionCount: number;
  flaggedChecklistCount: number;
  addedChecklistCount: number;
  recordLogExceptionCount: number;
  completedByUserId: number | null;
  completedByUserName: string | null;
  priority: string;
  tags: { tagId: number; label: string }[];
  businessDates: string[];
}

interface TrailTaskInstancesResponse {
  data: TrailTaskInstance[];
  page: { nextCursor: string | null };
}

// ----------------------------------------------------------------
// Metrics we extract per venue per week
// ----------------------------------------------------------------
export interface TrailVenueMetrics {
  venueId: string;
  trailSiteId: number;
  trailSiteName: string;
  weekEnding: string;
  // Completion stats
  totalTasks: number;
  completedTasks: number;
  notCompletedTasks: number;
  completionRate: number; // 0-100
  // Timing
  completedEarly: number;
  completedOnTime: number;
  completedLate: number;
  // Quality signals
  totalExceptions: number;
  totalFlagged: number;
  exceptionRate: number; // exceptions per completed task
  // Derived score for The Selector (0-100)
  trailScore: number;
}

// ----------------------------------------------------------------
// Trail Connector Class
// ----------------------------------------------------------------
export class TrailConnector {
  private client: AxiosInstance;
  private apiKey: string;

  constructor(apiKey: string) {
    this.apiKey = apiKey;
    this.client = axios.create({
      baseURL: BASE_URL,
      timeout: 30_000,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'API_KEY': apiKey,
      },
    });
  }

  // ----------------------------------------------------------------
  // TEST CONNECTION — fetch areas to verify key works
  // ----------------------------------------------------------------
  async testConnection(): Promise<{ success: boolean; message: string; areas: string[] }> {
    try {
      const response = await this.client.get<{ data: TrailArea[] }>('/areas/v1/list');
      const areas = (response.data.data ?? []).map(a => a.name);
      return {
        success: true,
        message: `Connected — ${areas.length} areas accessible`,
        areas,
      };
    } catch (err) {
      return {
        success: false,
        message: this.errorMessage(err),
        areas: [],
      };
    }
  }

  // ----------------------------------------------------------------
  // FETCH TASK INSTANCES for a date range
  // Handles pagination via cursor
  // ----------------------------------------------------------------
  async fetchTaskInstances(startDate: string, endDate: string): Promise<TrailTaskInstance[]> {
    const all: TrailTaskInstance[] = [];
    let cursor: string | null = null;

    do {
      const body: Record<string, unknown> = { startDate, endDate };
      if (cursor) body['pageStart'] = cursor;

      const response = await this.client.post<TrailTaskInstancesResponse>(
        '/task_reports/v1/task_instances',
        body,
      );

      all.push(...(response.data.data ?? []));
      cursor = response.data.page?.nextCursor ?? null;

      // Rate limit safety — 60 req/60s
      if (cursor) await sleep(1100);
    } while (cursor);

    return all;
  }

  // ----------------------------------------------------------------
  // COMPUTE weekly metrics per site from task instances
  // ----------------------------------------------------------------
  private computeSiteMetrics(
    venueId: string,
    trailSiteId: number,
    trailSiteName: string,
    weekEnding: string,
    tasks: TrailTaskInstance[],
  ): TrailVenueMetrics {
    const completed = tasks.filter(t =>
      t.status === 'completedEarly' ||
      t.status === 'completedOnTime' ||
      t.status === 'completedLate',
    );
    const notCompleted = tasks.filter(t => t.status === 'notCompleted');
    const early = tasks.filter(t => t.status === 'completedEarly');
    const onTime = tasks.filter(t => t.status === 'completedOnTime');
    const late = tasks.filter(t => t.status === 'completedLate');

    const totalTasks = tasks.length;
    const completedCount = completed.length;
    const completionRate = totalTasks > 0
      ? round2((completedCount / totalTasks) * 100)
      : 0;

    const totalExceptions = tasks.reduce((s, t) => s + (t.exceptionCount ?? 0), 0);
    const totalFlagged = tasks.reduce((s, t) => s + (t.flaggedChecklistCount ?? 0), 0);
    const exceptionRate = completedCount > 0
      ? round2(totalExceptions / completedCount)
      : 0;

    // Trail Score for The Selector (0-100)
    // Weighted: 70% completion rate + 20% timing bonus + 10% exception penalty
    const timingBonus = completedCount > 0
      ? ((early.length * 1.0 + onTime.length * 0.8 + late.length * 0.4) / completedCount) * 100
      : 0;
    const exceptionPenalty = Math.min(exceptionRate * 10, 20); // cap at 20 point penalty
    const trailScore = round2(
      Math.max(0, Math.min(100,
        (completionRate * 0.70) +
        (timingBonus * 0.20) -
        exceptionPenalty,
      )),
    );

    return {
      venueId,
      trailSiteId,
      trailSiteName,
      weekEnding,
      totalTasks,
      completedTasks: completedCount,
      notCompletedTasks: notCompleted.length,
      completionRate,
      completedEarly: early.length,
      completedOnTime: onTime.length,
      completedLate: late.length,
      totalExceptions,
      totalFlagged,
      exceptionRate,
      trailScore,
    };
  }

  // ----------------------------------------------------------------
  // SYNC — fetch one week for all venues
  // ----------------------------------------------------------------
  async syncAllVenues(weekEnding: string): Promise<void> {
    // Date range: Mon–Sun
    const weekEnd = new Date(weekEnding);
    const weekStart = new Date(weekEnd);
    weekStart.setDate(weekEnd.getDate() - 6);
    const startDate = weekStart.toISOString().split('T')[0]!;
    const endDate = weekEnding;

    console.log(`[Trail] Syncing week ${startDate} → ${endDate}`);

    // Fetch all task instances for the period
    const allTasks = await this.fetchTaskInstances(startDate, endDate);
    console.log(`[Trail] ${allTasks.length} task instances fetched`);

    // Group by siteId
    const bySite = new Map<number, TrailTaskInstance[]>();
    for (const task of allTasks) {
      const existing = bySite.get(task.siteId) ?? [];
      existing.push(task);
      bySite.set(task.siteId, existing);
    }

    // Get our venues from the database
    const venues = (await db.query<{ id: string; name: string; short_name: string }>(
      'SELECT id, name, short_name FROM venues WHERE is_active = true',
    )).rows;

    // Ensure the metrics table exists
    await this.ensureTable();

    // Match Trail sites to our venues by name and store metrics
    for (const [siteId, tasks] of bySite) {
      const siteName = tasks[0]!.siteName;

      // Fuzzy match to our venue
      const venue = venues.find(v =>
        v.name.toLowerCase().includes(siteName.toLowerCase().split(' ')[0]!) ||
        siteName.toLowerCase().includes(v.name.toLowerCase().split(' ')[0]!),
      );

      if (!venue) {
        console.warn(`[Trail] No venue match for Trail site "${siteName}" (id:${siteId})`);
        continue;
      }

      const metrics = this.computeSiteMetrics(venue.id, siteId, siteName, weekEnding, tasks);
      await this.storeMetrics(metrics);

      console.log(`[Trail] ✓ ${siteName} → ${venue.name}`);
      console.log(`  Tasks: ${metrics.totalTasks} | Completed: ${metrics.completedTasks} | Rate: ${metrics.completionRate}%`);
      console.log(`  Exceptions: ${metrics.totalExceptions} | Trail Score: ${metrics.trailScore}/100`);
    }
  }

  // ----------------------------------------------------------------
  // STORE metrics
  // ----------------------------------------------------------------
  private async storeMetrics(m: TrailVenueMetrics): Promise<void> {
    await db.query(
      `INSERT INTO trail_venue_metrics
         (id, venue_id, trail_site_id, trail_site_name, week_ending,
          total_tasks, completed_tasks, not_completed_tasks, completion_rate,
          completed_early, completed_on_time, completed_late,
          total_exceptions, total_flagged, exception_rate, trail_score)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
       ON CONFLICT (venue_id, week_ending) DO UPDATE
       SET total_tasks         = EXCLUDED.total_tasks,
           completed_tasks     = EXCLUDED.completed_tasks,
           not_completed_tasks = EXCLUDED.not_completed_tasks,
           completion_rate     = EXCLUDED.completion_rate,
           completed_early     = EXCLUDED.completed_early,
           completed_on_time   = EXCLUDED.completed_on_time,
           completed_late      = EXCLUDED.completed_late,
           total_exceptions    = EXCLUDED.total_exceptions,
           total_flagged       = EXCLUDED.total_flagged,
           exception_rate      = EXCLUDED.exception_rate,
           trail_score         = EXCLUDED.trail_score,
           synced_at           = NOW()`,
      [
        randomUUID(), m.venueId, m.trailSiteId, m.trailSiteName, m.weekEnding,
        m.totalTasks, m.completedTasks, m.notCompletedTasks, m.completionRate,
        m.completedEarly, m.completedOnTime, m.completedLate,
        m.totalExceptions, m.totalFlagged, m.exceptionRate, m.trailScore,
      ],
    );
  }

  private async ensureTable(): Promise<void> {
    await db.query(`
      CREATE TABLE IF NOT EXISTS trail_venue_metrics (
        id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        venue_id            UUID NOT NULL REFERENCES venues(id),
        trail_site_id       INTEGER NOT NULL,
        trail_site_name     VARCHAR(255),
        week_ending         DATE NOT NULL,
        total_tasks         INTEGER DEFAULT 0,
        completed_tasks     INTEGER DEFAULT 0,
        not_completed_tasks INTEGER DEFAULT 0,
        completion_rate     NUMERIC(5,2) DEFAULT 0,
        completed_early     INTEGER DEFAULT 0,
        completed_on_time   INTEGER DEFAULT 0,
        completed_late      INTEGER DEFAULT 0,
        total_exceptions    INTEGER DEFAULT 0,
        total_flagged       INTEGER DEFAULT 0,
        exception_rate      NUMERIC(6,3) DEFAULT 0,
        trail_score         NUMERIC(5,2) DEFAULT 0,
        synced_at           TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (venue_id, week_ending)
      )
    `);
  }

  private errorMessage(err: unknown): string {
    const e = err as AxiosError;
    if (e.response) return `HTTP ${e.response.status}: ${JSON.stringify(e.response.data)}`;
    return (e as Error).message ?? String(err);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

// ----------------------------------------------------------------
// Factory
// ----------------------------------------------------------------
export function createTrailConnector(): TrailConnector | null {
  const apiKey = process.env['TRAIL_API_KEY'];
  if (!apiKey) {
    console.warn('[Trail] TRAIL_API_KEY not set — connector disabled');
    return null;
  }
  return new TrailConnector(apiKey);
}
