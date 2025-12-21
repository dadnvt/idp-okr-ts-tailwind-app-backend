import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import crypto from 'node:crypto';
import { verifyCognito, requireLeader, requireManager } from './middleware/verifyCognito.js';

dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Optional timing logs: export LOG_TIMINGS=1 to enable.
const LOG_TIMINGS = process.env.LOG_TIMINGS === '1';
const SLOW_MS = Number(process.env.SLOW_MS || 800);
const nowMs = () => Number(process.hrtime.bigint()) / 1e6;

if (LOG_TIMINGS) {
  app.use((req, res, next) => {
    const start = nowMs();
    res.on('finish', () => {
      const ms = nowMs() - start;
      const line = `${req.method} ${req.originalUrl} -> ${res.statusCode} (${ms.toFixed(1)}ms)`;
      if (ms >= SLOW_MS) console.warn('[SLOW]', line);
      else console.log('[REQ]', line);
    });
    next();
  });
}

function isValidDateOnly(s) {
  return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
}

function toDateOnly(d) {
  return d.toISOString().slice(0, 10);
}

function parseDateOnly(s) {
  const [y, m, dd] = `${s}`.slice(0, 10).split('-').map(Number);
  const d = new Date(y, (m || 1) - 1, dd || 1);
  d.setHours(0, 0, 0, 0);
  return d;
}

function startOfWeekMonday(d) {
  const date = new Date(d);
  const day = (date.getDay() + 6) % 7; // Monday=0
  date.setHours(0, 0, 0, 0);
  date.setDate(date.getDate() - day);
  return date;
}

function weekKey(d) {
  return toDateOnly(startOfWeekMonday(d));
}

function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

function isLeaderUser(req) {
  const groups = req.user?.['cognito:groups'];
  const groupList = Array.isArray(groups) ? groups : typeof groups === 'string' ? [groups] : [];
  return groupList.includes('leader');
}

function bucketProgress(p) {
  const x = Math.max(0, Math.min(100, Number(p || 0)));
  if (x < 25) return '0_24';
  if (x < 50) return '25_49';
  if (x < 75) return '50_74';
  if (x < 100) return '75_99';
  return '100';
}

function parseMysqlUrl(urlStr) {
  const u = new URL(urlStr);
  const sslEnabled = u.searchParams.get('ssl') === '1' || u.searchParams.get('sslmode') === 'require';
  return {
    host: u.hostname,
    port: u.port ? Number(u.port) : 3306,
    user: decodeURIComponent(u.username || ''),
    password: decodeURIComponent(u.password || ''),
    database: (u.pathname || '').replace(/^\//, ''),
    ssl: sslEnabled ? { rejectUnauthorized: false } : undefined,
  };
}

const MYSQL_URL = process.env.RDS_MYSQL_URL || process.env.MYSQL_URL;
if (!MYSQL_URL) {
  throw new Error('Missing RDS_MYSQL_URL (or MYSQL_URL) env var for goal_mysql_v1.js');
}

const forceSsl = process.env.RDS_SSL === '1';
const mysqlCfg = parseMysqlUrl(MYSQL_URL);
if (forceSsl && !mysqlCfg.ssl) mysqlCfg.ssl = { rejectUnauthorized: false };

const pool = mysql.createPool({
  ...mysqlCfg,
  waitForConnections: true,
  connectionLimit: Number(process.env.MYSQL_MAX || 10),
  connectTimeout: Number(process.env.MYSQL_CONNECT_TIMEOUT_MS || 10_000),
  acquireTimeout: Number(process.env.MYSQL_ACQUIRE_TIMEOUT_MS || 10_000),
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
  // Keep DATE columns as YYYY-MM-DD strings (avoid JS Date -> timezone shifts)
  dateStrings: ['DATE'],
  // Numbers like DECIMAL should come back as JS numbers where possible
  decimalNumbers: true,
});

// Optional DB config log (safe): export LOG_DB=1 to enable.
if (process.env.LOG_DB === '1') {
  console.log('[DB]', 'mysql host=', mysqlCfg.host, 'port=', mysqlCfg.port, 'db=', mysqlCfg.database, 'ssl=', Boolean(mysqlCfg.ssl));
}

async function q(sqlText, params = []) {
  const [rows] = await pool.query(sqlText, params);
  return rows;
}

async function q1(sqlText, params = []) {
  const rows = await q(sqlText, params);
  return Array.isArray(rows) ? rows[0] || null : null;
}

function normalizeDbValue(v) {
  if (typeof v === 'undefined') return undefined;
  if (v === null) return null;
  if (v instanceof Date) return v.toISOString();
  if (typeof v === 'object') return JSON.stringify(v);
  return v;
}

function buildInsert(table, obj) {
  const entries = Object.entries(obj || {}).filter(([, v]) => typeof v !== 'undefined');
  const cols = entries.map(([k]) => `\`${k}\``);
  const vals = entries.map(([, v]) => normalizeDbValue(v));
  const qs = entries.map(() => '?');
  return { sql: `insert into \`${table}\` (${cols.join(',')}) values (${qs.join(',')})`, params: vals };
}

function buildUpdate(table, obj, whereSql, whereParams = []) {
  const entries = Object.entries(obj || {}).filter(([, v]) => typeof v !== 'undefined');
  const sets = entries.map(([k]) => `\`${k}\` = ?`);
  const vals = entries.map(([, v]) => normalizeDbValue(v));
  return { sql: `update \`${table}\` set ${sets.join(', ')} ${whereSql}`, params: [...vals, ...whereParams] };
}

function safeJsonParse(x) {
  if (x == null) return x;
  if (typeof x === 'object') return x;
  if (typeof x !== 'string') return x;
  const s = x.trim();
  if (!s) return x;
  try {
    return JSON.parse(s);
  } catch {
    return x;
  }
}

function hydrateRow(row) {
  if (!row || typeof row !== 'object') return row;
  const out = { ...row };
  for (const k of ['criteria', 'required_evidence', 'minimum_bar', 'evidence_links', 'rubric_snapshot', 'scores']) {
    if (typeof out[k] !== 'undefined') out[k] = safeJsonParse(out[k]);
  }
  return out;
}

function hydrateRows(rows) {
  return (Array.isArray(rows) ? rows : []).map(hydrateRow);
}

app.get('/healthz', (req, res) => {
  res.json({
    ok: true,
    service: 'idp-okr-backend',
    variant: 'goal_mysql_v1 (direct-mysql)',
    ts: new Date().toISOString(),
  });
});

// Public: list teams for signup dropdown
app.get('/public/teams', async (req, res) => {
  try {
    const rows = await q(`select id, name from teams order by name asc`, []);
    res.json({ data: Array.isArray(rows) ? rows : [] });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

function getGroupList(groups) {
  return Array.isArray(groups) ? groups : typeof groups === 'string' ? [groups] : [];
}

function deriveRoleFromGroups(groups) {
  const list = getGroupList(groups);
  if (list.includes('manager')) return 'manager';
  if (list.includes('leader')) return 'leader';
  return 'member';
}

function isUuidLike(s) {
  return typeof s === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
}

// Debug helper (auth required): shows Cognito identity + whether user exists in DB
// GET /me
app.get('/me', verifyCognito, async (req, res) => {
  const sub = req.user?.sub ?? null;
  const groups = req.user?.['cognito:groups'] ?? null;
  if (!sub) return res.status(401).json({ message: 'Missing identity (sub)' });

  try {
    const u = await q1(
      `
        select id, email, name, team_id, role
        from users
        where id = ?
        limit 1
      `,
      [sub]
    );
    res.json({
      data: {
        sub,
        groups: Array.isArray(groups) ? groups : typeof groups === 'string' ? [groups] : [],
        db_user: u
          ? { exists: true, id: u.id, email: u.email ?? null, name: u.name ?? null, team_id: u.team_id ?? null, role: u.role ?? null }
          : { exists: false },
      },
    });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e), sub });
  }
});

// Create/update user record in DB after Cognito login/signup.
// POST /auth/ensure-user
// Body: { email?: string, name?: string, team?: string, team_id?: string }
app.post('/auth/ensure-user', verifyCognito, async (req, res) => {
  const sub = req.user?.sub ?? null;
  if (!sub) return res.status(401).json({ message: 'Missing identity (sub)' });

  const body = req.body || {};
  const email = typeof body.email === 'string' ? body.email.trim() : null;
  const name = typeof body.name === 'string' ? body.name.trim() : null;
  const teamIdInput = typeof body.team_id === 'string' ? body.team_id.trim() : null;
  const teamInput = typeof body.team === 'string' ? body.team.trim() : null;
  const groups = req.user?.['cognito:groups'] ?? null;
  const role = deriveRoleFromGroups(groups);

  try {
    let team_id = null;
    const key = teamIdInput || teamInput || null;
    if (key) {
      const t = isUuidLike(key)
        ? await q1(`select id, name from teams where id = ? limit 1`, [key])
        : await q1(`select id, name from teams where lower(name) = lower(?) limit 1`, [key]);
      if (!t) {
        return res.status(400).json({
          message: `Team not found for "${key}". Please provide a valid team_id or team name (matches teams.name).`,
        });
      }
      team_id = t.id;
    }

    await q(
      `
        insert into users (id, email, name, team_id, role)
        values (?, ?, ?, ?, ?)
        as new
        on duplicate key update
          email = new.email,
          name = new.name,
          team_id = coalesce(new.team_id, users.team_id),
          role = new.role
      `,
      [sub, email, name, team_id, role]
    );

    const u = await q1(`select id, email, name, team_id, role from users where id = ? limit 1`, [sub]);
    return res.json({ data: hydrateRow(u) });
  } catch (e) {
    return res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

async function getLatestVerificationSummaryByGoalIds(goalIds) {
  const ids = Array.isArray(goalIds) ? goalIds.filter(Boolean) : [];
  if (ids.length === 0) return new Map();

  try {
    const rows = await q(
      `
        select
          x.id as verification_request_id,
          x.goal_id,
          x.status as verification_status,
          x.created_at as verification_requested_at,
          (
            select r.result
            from verification_reviews r
            where r.request_id = x.id
            order by r.reviewed_at desc
            limit 1
          ) as verification_result,
          (
            select r.reviewed_at
            from verification_reviews r
            where r.request_id = x.id
            order by r.reviewed_at desc
            limit 1
          ) as verification_reviewed_at
        from (
          select
            vr.*,
            row_number() over (partition by vr.goal_id order by vr.created_at desc) as rn
          from verification_requests vr
          where vr.goal_id in (?)
        ) x
        where x.rn = 1
      `,
      [ids]
    );

    const map = new Map();
    for (const r of hydrateRows(rows || [])) {
      map.set(r.goal_id, {
        verification_request_id: r.verification_request_id ?? null,
        verification_status: r.verification_status ?? 'NotRequested',
        verification_requested_at: r.verification_requested_at ?? null,
        verification_result: r.verification_result ?? null,
        verification_reviewed_at: r.verification_reviewed_at ?? null,
      });
    }
    return map;
  } catch (e) {
    console.warn('[WARN]', 'getLatestVerificationSummaryByGoalIds failed:', e instanceof Error ? e.message : String(e));
    return new Map();
  }
}

function attachVerificationSummaryToGoals(goals, summaryMap) {
  const map = summaryMap || new Map();
  return (goals || []).map((g) => {
    const v = map.get(g.id);
    return {
      ...g,
      verification_request_id: v?.verification_request_id ?? null,
      verification_status: v?.verification_status ?? 'NotRequested',
      verification_requested_at: v?.verification_requested_at ?? null,
      verification_result: v?.verification_result ?? null,
      verification_reviewed_at: v?.verification_reviewed_at ?? null,
    };
  });
}

// --- Manager APIs (org-wide read-only dashboard) ---

// GET /manager/teams (org-wide)
app.get('/manager/teams', verifyCognito, requireManager, async (req, res) => {
  try {
    const rows = await q(
      `
        select id, name
        from teams
        order by name asc
      `
    );
    res.json({ data: Array.isArray(rows) ? rows : [] });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

// GET /manager/users?team_id=<uuid>&limit=500&offset=0
app.get('/manager/users', verifyCognito, requireManager, async (req, res) => {
  const { team_id, limit, offset } = req.query;
  const pageLimit = Math.max(1, Math.min(1000, Number(limit || 500)));
  const pageOffset = Math.max(0, Number(offset || 0));
  const teamId = typeof team_id === 'string' && team_id.trim() ? team_id.trim() : null;

  try {
    const params = [];
    let where = '';
    if (teamId) {
      where = 'where u.team_id = ?';
      params.push(teamId);
    }

    const rows = await q(
      `
        select
          u.id,
          u.email,
          u.name,
          u.team_id,
          u.role,
          t.name as team_name
        from users u
        left join teams t on t.id = u.team_id
        ${where}
        order by u.name asc, u.email asc
        limit ?
        offset ?
      `,
      [...params, pageLimit, pageOffset]
    );

    const shaped =
      (Array.isArray(rows) ? rows : []).map((u) => ({
        id: u.id,
        email: u.email ?? null,
        name: u.name ?? null,
        team_id: u.team_id ?? null,
        team_name: u.team_name ?? null,
        role: u.role ?? null,
      })) || [];

    res.json({
      data: shaped,
      page: { limit: pageLimit, offset: pageOffset, returned: Array.isArray(rows) ? rows.length : 0 },
    });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

// NOTE: remaining manager endpoints + all member/leader/verification routes
// are ported below (MySQL 8).

// --- Access helpers ---

async function assertCanAccessGoal(req, goalId) {
  if (isLeaderUser(req)) return { ok: true };
  const userId = req.user.sub;
  const goal = await q1(`select id, user_id, status, is_locked, review_status from goals where id = ? limit 1`, [goalId]);
  if (!goal) return { ok: false, status: 404, message: 'Goal not found' };
  if (goal.user_id !== userId) return { ok: false, status: 403, message: 'Forbidden' };
  return { ok: true, goal };
}

async function assertCanAccessActionPlan(req, actionPlanId) {
  if (isLeaderUser(req)) return { ok: true };
  const userId = req.user.sub;
  const plan = await q1(`select id, goal_id from action_plans where id = ? limit 1`, [actionPlanId]);
  if (!plan) return { ok: false, status: 404, message: 'Action plan not found' };
  const goal = await q1(`select id, user_id from goals where id = ? limit 1`, [plan.goal_id]);
  if (!goal) return { ok: false, status: 404, message: 'Goal not found' };
  if (goal.user_id !== userId) return { ok: false, status: 403, message: 'Forbidden' };
  return { ok: true, plan, goal };
}

async function assertCanAccessWeeklyReport(req, weeklyReportId) {
  if (isLeaderUser(req)) return { ok: true };
  const report = await q1(`select id, action_plan_id from weekly_reports where id = ? limit 1`, [weeklyReportId]);
  if (!report) return { ok: false, status: 404, message: 'Weekly report not found' };
  const accessPlan = await assertCanAccessActionPlan(req, report.action_plan_id);
  if (!accessPlan.ok) return accessPlan;
  return { ok: true, report };
}

// --- Member APIs ---

app.post('/goals', verifyCognito, async (req, res) => {
  try {
    const goal = { ...(req.body || {}), user_id: req.user.sub };
    if (!goal.id) goal.id = crypto.randomUUID();
    const ins = buildInsert('goals', goal);
    await q(ins.sql, ins.params);
    const data = hydrateRow(await q1(`select * from goals where id = ? limit 1`, [goal.id]));
  res.json({ data });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.get('/goals', verifyCognito, async (req, res) => {
  const userId = req.user.sub;
  try {
    const rows = hydrateRows(await q(`select * from goals where user_id = ?`, [userId]));
    const goalIds = (rows || []).map((g) => g.id);
    const vmap = await getLatestVerificationSummaryByGoalIds(goalIds);
    const shaped = attachVerificationSummaryToGoals(rows || [], vmap);
    res.json({ data: shaped });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.put('/goals/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.sub;
  const { user_id, ...updates0 } = req.body || {};
  const updates = { ...updates0 };

  if (typeof updates?.progress !== 'undefined') {
    const n = Number(updates.progress);
    if (!Number.isNaN(n)) {
      const clamped = Math.max(0, Math.min(100, n));
      updates.progress = clamped;
      if (clamped >= 100) updates.status = 'Completed';
    }
  }

  try {
    const goal = await q1(`select id, user_id, is_locked, review_status from goals where id = ? limit 1`, [id]);
    if (!goal) return res.status(404).json({ message: 'Goal not found' });
    if (goal.user_id !== userId) return res.status(403).json({ message: 'Forbidden' });

  if (goal.is_locked) {
    if (goal.review_status === 'Approved') {
      const keys = Object.keys(updates || {});
        const allowedKeys = new Set(['progress', 'status']);
      const hasDisallowed = keys.some((k) => !allowedKeys.has(k));
        if (hasDisallowed) return res.status(423).json({ message: 'Goal is locked (only status/progress updates are allowed)' });
    } else {
      return res.status(423).json({ message: 'Goal is locked for review' });
    }
  }

    const upd = buildUpdate('goals', { ...updates, updated_at: new Date().toISOString() }, 'where id = ?', [id]);
    await q(upd.sql, upd.params);
    const data = hydrateRow(await q1(`select * from goals where id = ? limit 1`, [id]));
    if (!data) return res.status(404).json({ message: 'Goal not found' });
  res.json({ data });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.post('/goals/:id/request-review', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.sub;
  try {
    const goal = await q1(`select id, user_id, review_status, is_locked from goals where id = ? limit 1`, [id]);
    if (!goal) return res.status(404).json({ message: 'Goal not found' });
  if (goal.user_id !== userId) return res.status(403).json({ message: 'Forbidden' });
    if (goal.review_status === 'Approved') return res.status(409).json({ message: 'Goal already approved' });

    const anyPlan = await q1(`select id from action_plans where goal_id = ? limit 1`, [id]);
    if (!anyPlan) {
      return res.status(409).json({ message: 'You must create at least one action plan before requesting leader review' });
    }

    const upd = buildUpdate('goals', { review_status: 'Pending', is_locked: 1 }, 'where id = ?', [id]);
    await q(upd.sql, upd.params);
    const data = hydrateRow(await q1(`select * from goals where id = ? limit 1`, [id]));
    res.json({ data: data || null });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.post('/goals/:id/cancel-review', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.sub;
  try {
    const goal = await q1(`select id, user_id, review_status, is_locked from goals where id = ? limit 1`, [id]);
    if (!goal) return res.status(404).json({ message: 'Goal not found' });
  if (goal.user_id !== userId) return res.status(403).json({ message: 'Forbidden' });
    if (goal.review_status === 'Approved') return res.status(409).json({ message: 'Goal already approved' });

    const upd = buildUpdate('goals', { review_status: 'Cancelled', is_locked: 0 }, 'where id = ?', [id]);
    await q(upd.sql, upd.params);
    const data = hydrateRow(await q1(`select * from goals where id = ? limit 1`, [id]));
    res.json({ data: data || null });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.get('/action-plans', verifyCognito, async (req, res) => {
  const userId = req.user.sub;
  const { year } = req.query;
  const targetYear = Number(year);
  const t0 = LOG_TIMINGS ? nowMs() : 0;

  try {
    const goals = hydrateRows(await q(`select * from goals where user_id = ? and year = ?`, [userId, targetYear]));
    const goalIds = (goals || []).map((g) => g.id).filter(Boolean);
    let plans = [];
    if (goalIds.length > 0) {
      plans = hydrateRows(await q(`select * from action_plans where goal_id in (?)`, [goalIds]));
    }

    const plansByGoal = new Map();
    for (const p of plans || []) {
      const gid = p.goal_id;
      if (!gid) continue;
      if (!plansByGoal.has(gid)) plansByGoal.set(gid, []);
      plansByGoal.get(gid).push(p);
    }

    const shaped = (goals || []).map((g) => ({ ...g, action_plans: plansByGoal.get(g.id) || [] }));

    if (LOG_TIMINGS) {
      const ms = nowMs() - t0;
      const n = Array.isArray(goals) ? goals.length : 0;
      console.log('[DB]', `GET /action-plans mysql (${ms.toFixed(1)}ms) goals=${n}`);
    }

    res.json({ data: shaped });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.get('/action-plans/:actionPlanId/weekly-reports', verifyCognito, async (req, res) => {
  const { actionPlanId } = req.params;
  const limit = Math.max(1, Math.min(100, Number(req.query.limit || 20)));
  const offset = Math.max(0, Number(req.query.offset || 0));
  const access = await assertCanAccessActionPlan(req, actionPlanId);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  const t0 = LOG_TIMINGS ? nowMs() : 0;
  try {
    const rows = hydrateRows(
      await q(`select * from weekly_reports where action_plan_id = ? order by date desc limit ? offset ?`, [
        actionPlanId,
        limit,
        offset,
      ])
    );

    if (LOG_TIMINGS) {
      const ms = nowMs() - t0;
      const count = Array.isArray(rows) ? rows.length : 0;
      console.log('[DB]', `GET /action-plans/:id/weekly-reports mysql (${ms.toFixed(1)}ms) rows=${count} limit=${limit} offset=${offset}`);
    }

    res.json({ data: rows || [], page: { limit, offset, returned: Array.isArray(rows) ? rows.length : 0 } });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.post('/goals/:goalId/action-plans', verifyCognito, async (req, res) => {
  const { goalId } = req.params;
  try {
  const access = await assertCanAccessGoal(req, goalId);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  if (!isLeaderUser(req)) {
      if (access.goal?.is_locked) return res.status(423).json({ message: 'Goal is locked for review' });
      if (access.goal?.status !== 'Not started') return res.status(409).json({ message: 'Cannot add action plans after goal has started' });
    }

    const actionPlan = { ...(req.body || {}), goal_id: goalId };
    if (!actionPlan.id) actionPlan.id = crypto.randomUUID();
    const ins = buildInsert('action_plans', actionPlan);
    await q(ins.sql, ins.params);
    const data = hydrateRow(await q1(`select * from action_plans where id = ? limit 1`, [actionPlan.id]));
    res.json({ data });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.delete('/action-plans/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const access = await assertCanAccessActionPlan(req, id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  try {
  if (!isLeaderUser(req)) {
      const plan = await q1(`select id, is_locked from action_plans where id = ? limit 1`, [id]);
      if (!plan) return res.status(404).json({ message: 'Action plan not found' });
    if (plan.is_locked) return res.status(423).json({ message: 'Action plan is locked for review' });
  }

    await q(`delete from action_plans where id = ?`, [id]);
  res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.put('/action-plans/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const access = await assertCanAccessActionPlan(req, id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  try {
  let existingPlan = null;
  if (!isLeaderUser(req)) {
      const plan = await q1(
        `select id, is_locked, review_status, status, start_date, end_date, request_deadline_date, deadline_change_count from action_plans where id = ? limit 1`,
        [id]
      );
      if (!plan) return res.status(404).json({ message: 'Action plan not found' });
    existingPlan = plan;

    if (plan.is_locked && plan.review_status === 'Pending') {
      const keys = Object.keys(req.body || {});
      const allowedKeys = new Set(['end_date']);
      const hasDisallowed = keys.some((k) => !allowedKeys.has(k));
        if (hasDisallowed) return res.status(423).json({ message: 'Action plan is locked for review (deadline-only changes allowed)' });
    }

    if (plan.review_status === 'Pending' && typeof req.body?.status !== 'undefined' && req.body.status !== plan.status) {
      return res.status(409).json({ message: 'Cannot change status while action plan is pending review' });
    }
  }

  let updates = { ...(req.body || {}) };
  if (!isLeaderUser(req) && existingPlan) {
    if (typeof updates.end_date === 'string') {
      const desired = updates.end_date;
      const currentRequested = existingPlan.request_deadline_date || null;
      const currentEffective = currentRequested || existingPlan.end_date;
      if (desired && desired !== currentEffective) {
        const count = Number(existingPlan.deadline_change_count || 0);
          if (count >= 3) return res.status(409).json({ message: 'Deadline can only be changed 3 times' });
        updates = {
          ...updates,
          request_deadline_date: desired,
          deadline_change_count: count + 1,
          review_status: 'Pending',
            is_locked: 1,
          leader_review_notes: null,
        };
      }
      delete updates.end_date;
    }
  }

    const upd = buildUpdate('action_plans', updates, 'where id = ?', [id]);
    await q(upd.sql, upd.params);
    const data = hydrateRow(await q1(`select * from action_plans where id = ? limit 1`, [id]));
    res.json({ data });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.post('/action-plans/:id/request-review', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const access = await assertCanAccessActionPlan(req, id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });
  if (isLeaderUser(req)) return res.status(403).json({ message: 'Forbidden' });

  try {
    const plan = await q1(`select id, review_status from action_plans where id = ? limit 1`, [id]);
    if (!plan) return res.status(404).json({ message: 'Action plan not found' });
  if (plan.review_status === 'Approved') return res.status(409).json({ message: 'Action plan already approved' });
    const upd = buildUpdate('action_plans', { review_status: 'Pending', is_locked: 1 }, 'where id = ?', [id]);
    await q(upd.sql, upd.params);
    const data = hydrateRow(await q1(`select * from action_plans where id = ? limit 1`, [id]));
    res.json({ data: data || null });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.post('/action-plans/:id/cancel-review', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const access = await assertCanAccessActionPlan(req, id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });
  if (isLeaderUser(req)) return res.status(403).json({ message: 'Forbidden' });

  try {
    const plan = await q1(`select id, review_status from action_plans where id = ? limit 1`, [id]);
    if (!plan) return res.status(404).json({ message: 'Action plan not found' });
  if (plan.review_status === 'Approved') return res.status(409).json({ message: 'Action plan already approved' });
    const upd = buildUpdate('action_plans', { review_status: null, is_locked: 0, request_deadline_date: null }, 'where id = ?', [id]);
    await q(upd.sql, upd.params);
    const data = hydrateRow(await q1(`select * from action_plans where id = ? limit 1`, [id]));
    res.json({ data: data || null });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.post('/action-plans/:actionPlanId/weekly-reports', verifyCognito, async (req, res) => {
  const { actionPlanId } = req.params;
  const access = await assertCanAccessActionPlan(req, actionPlanId);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  try {
    const plan = await q1(`select id, goal_id, status from action_plans where id = ? limit 1`, [actionPlanId]);
    if (!plan) return res.status(404).json({ message: 'Action plan not found' });

  if (!isLeaderUser(req)) {
      const goal = await q1(`select id, status from goals where id = ? limit 1`, [plan.goal_id]);
      if (!goal) return res.status(404).json({ message: 'Goal not found' });
    const planStatus = plan.status || 'Not Started';
      const canReport = goal.status === 'In Progress' && (planStatus === 'In Progress' || planStatus === 'Blocked');
    if (!canReport) {
      return res.status(409).json({
        message: 'Weekly reports can only be added when goal is In Progress and action plan is In Progress/Blocked',
      });
    }
  }

    const weeklyReport = { ...(req.body || {}), action_plan_id: actionPlanId, goal_id: plan.goal_id };
    if (!weeklyReport.id) weeklyReport.id = crypto.randomUUID();
    const ins = buildInsert('weekly_reports', weeklyReport);
    await q(ins.sql, ins.params);
    const data = hydrateRow(await q1(`select * from weekly_reports where id = ? limit 1`, [weeklyReport.id]));
    res.json({ data });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.put('/weekly-reports/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const access = await assertCanAccessWeeklyReport(req, id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  if (!isLeaderUser(req) && typeof req.body?.lead_feedback !== 'undefined') {
    return res.status(403).json({ message: 'Forbidden (leader feedback is leader-only)' });
  }

  try {
    const upd = buildUpdate('weekly_reports', req.body || {}, 'where id = ?', [id]);
    await q(upd.sql, upd.params);
    const data = hydrateRow(await q1(`select * from weekly_reports where id = ? limit 1`, [id]));
    res.json({ data });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.delete('/weekly-reports/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const access = await assertCanAccessWeeklyReport(req, id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  try {
    await q(`delete from weekly_reports where id = ?`, [id]);
  res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.delete('/goals/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.sub;
  try {
    const goal = await q1(`select id, user_id, is_locked from goals where id = ? limit 1`, [id]);
    if (!goal) return res.status(404).json({ message: 'Goal not found' });
    if (goal.user_id !== userId) return res.status(403).json({ message: 'Forbidden' });
    if (goal.is_locked) return res.status(423).json({ message: 'Goal is locked for review' });
    await q(`delete from goals where id = ?`, [id]);
    res.json({ message: 'Goal deleted successfully' });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

// --- Leader APIs (team-scoped) ---

async function getLeaderTeamScope(req) {
  const leaderId = req.user?.sub;
  if (!leaderId) return { ok: false, status: 401, message: 'Missing leader identity' };
  if (process.env.LOG_AUTH === '1') console.log('[AUTH]', 'getLeaderTeamScope leaderId=', leaderId);

  try {
    const data = await q1(
      `
        select u.id, u.team_id, t.name as team_name
        from users u
        left join teams t on t.id = u.team_id
        where u.id = ?
        limit 1
      `,
      [leaderId]
    );
    if (!data) {
      return { ok: false, status: 403, message: `Leader not found in users (id=${leaderId}). Please insert/sync leader into users table with team_id.` };
    }
    if (!data.team_id) {
      return { ok: false, status: 403, message: `Leader is not assigned to a team (users.team_id is null for id=${leaderId})` };
    }
    return { ok: true, teamId: data.team_id, teamName: data.team_name ?? null };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (process.env.LOG_AUTH === '1') console.warn('[AUTH]', 'getLeaderTeamScope failed:', msg);
    return { ok: false, status: 500, message: `Leader team scope query failed: ${msg}` };
  }
}

app.get('/leader/goals', verifyCognito, requireLeader, async (req, res) => {
  const t0 = LOG_TIMINGS ? nowMs() : 0;
  const { year, user_id, team_id, limit, offset } = req.query;
  const pageLimit = Math.max(1, Math.min(500, Number(limit || 200)));
  const pageOffset = Math.max(0, Number(offset || 0));

  try {
    const scope = await getLeaderTeamScope(req);
    if (!scope.ok) return res.status(scope.status).json({ message: scope.message });

    if (typeof team_id === 'string' && team_id.trim() && team_id.trim() !== scope.teamId) {
      return res.status(403).json({ message: 'Forbidden (team scope)' });
    }

    const params = [scope.teamId];
    let where = 'where u.team_id = ?';
    if (typeof year !== 'undefined' && year !== null && `${year}`.trim() !== '') {
      where += ' and g.year = ?';
      params.push(Number(year));
    }
    if (typeof user_id === 'string' && user_id.trim()) {
      where += ' and g.user_id = ?';
      params.push(user_id.trim());
    }

    const goals = hydrateRows(
      await q(
        `
          select
            g.*,
            u.id as member_id,
            u.email as member_email,
            u.name as member_name,
            u.team_id as member_team_id,
            t.name as member_team_name
          from goals g
          join users u on u.id = g.user_id
          left join teams t on t.id = u.team_id
          ${where}
          limit ?
          offset ?
        `,
        [...params, pageLimit, pageOffset]
      )
    );

    const goalIds = (goals || []).map((g) => g.id).filter(Boolean);
    let plans = [];
    if (goalIds.length > 0) {
      plans = hydrateRows(await q(`select * from action_plans where goal_id in (?)`, [goalIds]));
    }

    const plansByGoal = new Map();
    for (const p of plans || []) {
      const gid = p.goal_id;
      if (!gid) continue;
      if (!plansByGoal.has(gid)) plansByGoal.set(gid, []);
      plansByGoal.get(gid).push(p);
    }

    const shaped =
      (goals || []).map((g) => ({
        ...g,
        action_plans: plansByGoal.get(g.id) || [],
        user_name: g.member_name ?? g.user_name ?? null,
        user_email: g.member_email ?? g.user_email ?? null,
        team_id: g.member_team_id ?? g.team_id ?? null,
        team: g.member_team_name ?? g.team ?? null,
      })) || [];

    const cleaned = shaped.map((g) => {
      const { member_id, member_email, member_name, member_team_id, member_team_name, ...rest } = g;
      return rest;
    });

    const vmap = await getLatestVerificationSummaryByGoalIds(goalIds);
    const withVerify = attachVerificationSummaryToGoals(cleaned, vmap);

    if (LOG_TIMINGS) {
      const ms = nowMs() - t0;
      const n = Array.isArray(goals) ? goals.length : 0;
      console.log('[DB]', `GET /leader/goals mysql (${ms.toFixed(1)}ms) goals=${n} limit=${pageLimit} offset=${pageOffset}`);
    }

    res.json({ data: withVerify });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.get('/leader/goals/summary', verifyCognito, requireLeader, async (req, res) => {
  const t0 = LOG_TIMINGS ? nowMs() : 0;
  const { year, user_id, team_id } = req.query;

  const scope = await getLeaderTeamScope(req);
  if (!scope.ok) return res.status(scope.status).json({ message: scope.message });
  if (typeof team_id === 'string' && team_id.trim() && team_id.trim() !== scope.teamId) {
    return res.status(403).json({ message: 'Forbidden (team scope)' });
  }

  const targetYear = typeof year !== 'undefined' && year !== null && `${year}`.trim() !== '' ? Number(year) : null;
  if (!targetYear || Number.isNaN(targetYear)) return res.status(400).json({ error: 'Query param "year" is required (number)' });

  try {
    const params = [targetYear, scope.teamId];
    let whereUser = '';
    if (typeof user_id === 'string' && user_id.trim()) {
      whereUser = 'and g.user_id = ?';
      params.push(user_id.trim());
    }

    const row =
      (await q1(
        `
          select
            count(*) as total,
            sum(case when g.review_status = 'Approved' then 1 else 0 end) as approved,
            sum(case when g.review_status is null or g.review_status = 'Pending' then 1 else 0 end) as pending,
            coalesce(avg(coalesce(g.progress, 0)), 0) as avg_progress
          from goals g
          join users u on u.id = g.user_id
          where g.year = ?
            and u.team_id = ?
            ${whereUser}
        `,
        params
      )) || { total: 0, approved: 0, pending: 0, avg_progress: 0 };

    if (LOG_TIMINGS) {
      const ms = nowMs() - t0;
      console.log('[DB]', `GET /leader/goals/summary mysql (${ms.toFixed(1)}ms) total=${row.total} year=${targetYear}`);
    }

    res.json({
      data: {
        total: Number(row.total || 0),
        approved: Number(row.approved || 0),
        pending: Number(row.pending || 0),
        avgProgress: Number(row.avg_progress || 0),
      },
    });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.get('/leader/users', verifyCognito, requireLeader, async (req, res) => {
  const { q: qtext, team, team_id, limit, offset } = req.query;
  const pageLimit = Math.max(1, Math.min(500, Number(limit || 200)));
  const pageOffset = Math.max(0, Number(offset || 0));
  const scope = await getLeaderTeamScope(req);
  if (!scope.ok) return res.status(scope.status).json({ message: scope.message });

  const t0 = LOG_TIMINGS ? nowMs() : 0;
  const teamId =
    typeof team_id === 'string' && team_id.trim()
      ? team_id.trim()
      : typeof team === 'string' && team.trim()
        ? team.trim()
        : null;
  if (teamId && teamId !== scope.teamId) return res.status(403).json({ message: 'Forbidden (team scope)' });

  const needle = typeof qtext === 'string' && qtext.trim() ? qtext.trim() : null;
  try {
    const params = [scope.teamId];
    let search = '';
    if (needle) {
      search = 'and (lower(u.name) like ? or lower(u.email) like ?)';
      const pat = `%${needle.toLowerCase()}%`;
      params.push(pat, pat);
    }

    const rows = await q(
      `
        select
          u.id,
          u.email,
          u.name,
          u.team_id,
          u.role,
          t.name as team_name
        from users u
        left join teams t on t.id = u.team_id
        where u.team_id = ?
        ${search}
        order by u.name asc, u.email asc
        limit ?
        offset ?
      `,
      [...params, pageLimit, pageOffset]
    );

    if (LOG_TIMINGS) {
      const ms = nowMs() - t0;
      const rowsN = Array.isArray(rows) ? rows.length : 0;
      console.log('[DB]', `GET /leader/users mysql (${ms.toFixed(1)}ms) rows=${rowsN} limit=${pageLimit} offset=${pageOffset}`);
    }

    const shaped =
      (rows || []).map((u) => ({
        id: u.id,
        email: u.email ?? null,
        name: u.name ?? null,
        team_id: u.team_id ?? null,
        team_name: u.team_name ?? null,
        role: u.role ?? null,
      })) || [];

    res.json({ data: shaped, page: { limit: pageLimit, offset: pageOffset, returned: shaped.length } });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.get('/leader/teams', verifyCognito, requireLeader, async (req, res) => {
  const scope = await getLeaderTeamScope(req);
  if (!scope.ok) return res.status(scope.status).json({ message: scope.message });
  try {
    const rows = await q(`select id, name from teams where id = ? order by name asc`, [scope.teamId]);
    res.json({ data: rows || [] });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

async function computeMemberInsights({ userId, targetYear, lookbackWeeks }) {
  const now = new Date();
  const thisWeekStart = startOfWeekMonday(now);
  const from = new Date(thisWeekStart);
  from.setDate(from.getDate() - (lookbackWeeks - 1) * 7);
  const fromStr = toDateOnly(from);
  const toStr = toDateOnly(now);

  const goals = hydrateRows(
    await q(
      `
        select id, user_id, year, progress, status, review_status, start_date, time_bound, updated_at
        from goals
        where user_id = ?
          and year = ?
      `,
      [userId, targetYear]
    )
  );

  const goalIds = (goals || []).map((g) => g.id).filter(Boolean);
  const goalProgressById = new Map((goals || []).map((g) => [g.id, Number(g.progress || 0)]));

  const plans = hydrateRows(
    await q(
      `
        select ap.id, ap.goal_id, ap.status, ap.start_date, ap.end_date, ap.evidence_link
        from action_plans ap
        join goals g on g.id = ap.goal_id
        where g.user_id = ?
          and g.year = ?
      `,
      [userId, targetYear]
    )
  );

  const reports = hydrateRows(
    await q(
      `
        select wr.goal_id, wr.action_plan_id, wr.date, wr.blockers_challenges
        from weekly_reports wr
        join goals g on g.id = wr.goal_id
        where g.user_id = ?
          and g.year = ?
          and wr.date >= ?
          and wr.date <= ?
      `,
      [userId, targetYear, fromStr, toStr]
    )
  );

  let progressDelta = null;
  try {
    if (goalIds.length > 0) {
      const curCutoff = now;
      const prevCutoff = new Date(thisWeekStart);
      prevCutoff.setMilliseconds(prevCutoff.getMilliseconds() - 1);
      const historyFrom = new Date(prevCutoff);
      historyFrom.setDate(historyFrom.getDate() - Math.max(14, lookbackWeeks * 7));

      const hist = hydrateRows(
        await q(
          `
            select goal_id, progress, recorded_at
            from goal_progress_history
            where goal_id in (?)
              and recorded_at >= ?
              and recorded_at <= ?
            order by recorded_at desc
          `,
          [goalIds, historyFrom.toISOString(), curCutoff.toISOString()]
        )
      );

      const cur = new Map();
      const prev = new Map();
      for (const row of hist || []) {
        const gid = row.goal_id;
        if (!gid) continue;
        const recAt = row.recorded_at ? new Date(row.recorded_at) : null;
        if (!recAt || Number.isNaN(recAt.getTime())) continue;
        const p = Number(row.progress || 0);
        if (!cur.has(gid)) cur.set(gid, p);
        if (!prev.has(gid) && recAt.getTime() <= prevCutoff.getTime()) prev.set(gid, p);
        if (cur.size === goalIds.length && prev.size === goalIds.length) break;
      }

      const curVals = [];
      const prevVals = [];
      for (const gid of goalIds) {
        const curP = cur.has(gid) ? cur.get(gid) : goalProgressById.get(gid) ?? 0;
        const prevP = prev.has(gid) ? prev.get(gid) : curP;
        curVals.push(curP);
        prevVals.push(prevP);
      }
      const avg = (xs) => (xs.length ? xs.reduce((s, x) => s + x, 0) / xs.length : 0);
      progressDelta = Number((avg(curVals) - avg(prevVals)).toFixed(2));
    }
  } catch {
    progressDelta = null;
  }

  const totalGoals = (goals || []).length;
  const approvedGoals = (goals || []).filter((g) => g.review_status === 'Approved').length;
  const pendingGoals = (goals || []).filter((g) => !g.review_status || g.review_status === 'Pending').length;

  const msDay = 24 * 3600 * 1000;
  const goalHealth = { onTrack: 0, atRisk: 0, highRisk: 0, stagnant: 0 };
  for (const g of goals || []) {
    const start = g.start_date ? new Date(g.start_date) : null;
    const end = g.time_bound ? new Date(g.time_bound) : null;
    const progress = Number(g.progress || 0);
    if (g.review_status === 'Approved' && progress <= 0 && start) {
      const days = Math.floor((now.getTime() - start.getTime()) / msDay);
      if (days > 10) goalHealth.stagnant += 1;
    }
    if (!start || !end) continue;
    const total = end.getTime() - start.getTime();
    if (total <= 0) continue;
    const elapsed = now.getTime() - start.getTime();
    const expected = Math.min(100, Math.round((elapsed / total) * 100));
    if (progress < expected - 20) goalHealth.highRisk += 1;
    else if (progress < expected - 10) goalHealth.atRisk += 1;
    else goalHealth.onTrack += 1;
  }

  const allPlans = plans || [];
  const totalPlans = allPlans.length;
  const completedPlans = allPlans.filter((p) => p.status === 'Completed');
  const completedWithEvidence = completedPlans.filter((p) => (typeof p.evidence_link === 'string' ? p.evidence_link.trim() : '').length > 0);
  const evidenceRate = completedPlans.length > 0 ? completedWithEvidence.length / completedPlans.length : 0;

  const todayStart = new Date(now);
  todayStart.setHours(0, 0, 0, 0);
  const overduePlans = allPlans.filter((p) => {
    if (!p.end_date) return false;
    const end = parseDateOnly(p.end_date);
    if (Number.isNaN(end.getTime())) return false;
    if (p.status === 'Completed') return false;
    return end.getTime() < todayStart.getTime();
  });

  const weeksWithActivity = new Set();
  const blockersCount = new Map();
  for (const r of reports || []) {
    const dateOnly = typeof r.date === 'string' ? r.date.slice(0, 10) : null;
    if (!isValidDateOnly(dateOnly)) continue;
    weeksWithActivity.add(weekKey(parseDateOnly(dateOnly)));
    const b = typeof r.blockers_challenges === 'string' ? r.blockers_challenges.trim() : '';
    if (b) blockersCount.set(b, (blockersCount.get(b) || 0) + 1);
  }

  let streakWeeks = 0;
  for (let i = 0; i < lookbackWeeks; i++) {
    const d = new Date(thisWeekStart);
    d.setDate(d.getDate() - i * 7);
    if (weeksWithActivity.has(weekKey(d))) streakWeeks += 1;
    else break;
  }

  const topBlockers = Array.from(blockersCount.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([text, count]) => ({ text, count }));

  return {
    window: { from: fromStr, to: toStr, weeks: lookbackWeeks },
    goals: { total: totalGoals, approved: approvedGoals, pending: pendingGoals, health: goalHealth },
    action_plans: {
      total: totalPlans,
      overdue: overduePlans.length,
      completed: completedPlans.length,
      completed_with_evidence: completedWithEvidence.length,
      evidence_rate: evidenceRate,
    },
    weekly_reports: {
      reports_in_window: (reports || []).length,
      weeks_with_activity: weeksWithActivity.size,
      streak_weeks: streakWeeks,
      top_blockers: topBlockers,
    },
    progress_delta: progressDelta,
  };
}

// GET /manager/member-insights?year=2025&user_id=<uuid>&weeks=8
app.get('/manager/member-insights', verifyCognito, requireManager, async (req, res) => {
  const { year, user_id, weeks } = req.query;
  const targetYear = Number(year);
  if (!targetYear || Number.isNaN(targetYear)) return res.status(400).json({ error: 'Query param "year" is required (number)' });
  if (typeof user_id !== 'string' || !user_id.trim()) return res.status(400).json({ error: 'Query param "user_id" is required' });
  const userId = user_id.trim();
  const lookbackWeeks = Math.max(1, Math.min(26, Number(weeks || 8)));

  try {
    const data = await computeMemberInsights({ userId, targetYear, lookbackWeeks });
    res.json({ data: { user_id: userId, year: targetYear, ...data } });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

// GET /leader/member-insights?year=2025&user_id=<uuid>&weeks=8
app.get('/leader/member-insights', verifyCognito, requireLeader, async (req, res) => {
  const { year, user_id, weeks } = req.query;
  const targetYear = Number(year);
  if (!targetYear || Number.isNaN(targetYear)) return res.status(400).json({ error: 'Query param "year" is required (number)' });
  if (typeof user_id !== 'string' || !user_id.trim()) return res.status(400).json({ error: 'Query param "user_id" is required' });
  const userId = user_id.trim();
  const lookbackWeeks = Math.max(1, Math.min(26, Number(weeks || 8)));

  try {
    const scope = await getLeaderTeamScope(req);
    if (!scope.ok) return res.status(scope.status).json({ message: scope.message });
    const u = await q1(`select id, team_id from users where id = ? limit 1`, [userId]);
    if (!u) return res.status(404).json({ message: 'User not found' });
    if (u.team_id !== scope.teamId) return res.status(403).json({ message: 'Forbidden (team scope)' });

    const data = await computeMemberInsights({ userId, targetYear, lookbackWeeks });
    res.json({ data: { user_id: userId, year: targetYear, ...data } });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

// --- Manager overview / summary / trends ---

app.get('/manager/overview', verifyCognito, requireManager, async (req, res) => {
  const { year, team_id, weeks } = req.query;
  const targetYear = Number(year);
  if (!targetYear || Number.isNaN(targetYear)) return res.status(400).json({ error: 'Query param "year" is required (number)' });
  const lookbackWeeks = Math.max(1, Math.min(26, Number(weeks || 8)));
  const teamId = typeof team_id === 'string' && team_id.trim() ? team_id.trim() : null;

  const now = new Date();
  const thisWeekStart = startOfWeekMonday(now);
  const from = new Date(thisWeekStart);
  from.setDate(from.getDate() - (lookbackWeeks - 1) * 7);
  const fromStr = toDateOnly(from);
  const toStr = toDateOnly(now);

  const t0 = LOG_TIMINGS ? nowMs() : 0;
  try {
    const teams = await q(`select id, name from teams order by name asc`, []);
    const users = await q(teamId ? `select id, team_id, role from users where team_id = ?` : `select id, team_id, role from users`, teamId ? [teamId] : []);

    const userTeam = new Map((users || []).map((u) => [u.id, u.team_id || null]));
    const membersTotalByTeam = new Map();
    for (const u of users || []) {
      const tid = u.team_id || null;
      if (!tid) continue;
      membersTotalByTeam.set(tid, (membersTotalByTeam.get(tid) || 0) + 1);
    }

    const initTeamAgg = () => ({
      members_total: 0,
      members_with_goal: 0,
      goals_total: 0,
      goals_review: { approved: 0, pending: 0 },
      progress_avg: 0,
      progress_buckets: { '0_24': 0, '25_49': 0, '50_74': 0, '75_99': 0, '100': 0 },
      action_plans: { total: 0, overdue: 0, completed: 0, completed_with_evidence: 0, evidence_rate: 0 },
      weekly_reports: { reports_in_window: 0, active_members_this_week: 0, active_rate_this_week: 0 },
      verifications: { pending: 0, reviewed: 0 },
      progress_delta: null,
    });

    const teamAgg = new Map();
    for (const t of teams || []) {
      if (teamId && t.id !== teamId) continue;
      teamAgg.set(t.id, initTeamAgg());
    }
    for (const [tid, c] of membersTotalByTeam.entries()) {
      if (!teamAgg.has(tid)) teamAgg.set(tid, initTeamAgg());
      teamAgg.get(tid).members_total = c;
    }

    const goalsRaw = await q(
      `
        select g.id, g.user_id, g.progress, g.review_status, u.team_id as team_id
        from goals g
        join users u on u.id = g.user_id
        where g.year = ?
        ${teamId ? 'and u.team_id = ?' : ''}
      `,
      teamId ? [targetYear, teamId] : [targetYear]
    );

    const goals = (goalsRaw || []).map((g) => ({
      id: g.id,
      user_id: g.user_id,
      progress: Number(g.progress || 0),
      review_status: g.review_status || null,
      team_id: g.team_id ?? userTeam.get(g.user_id) ?? null,
    }));

    const memberHasGoal = new Set();
    const goalsByTeam = new Map();
    for (const g of goals) {
      const tid = g.team_id;
      if (!tid) continue;
      if (!teamAgg.has(tid)) teamAgg.set(tid, initTeamAgg());
      const agg = teamAgg.get(tid);
      agg.goals_total += 1;
      if (g.review_status === 'Approved') agg.goals_review.approved += 1;
      if (!g.review_status || g.review_status === 'Pending') agg.goals_review.pending += 1;
      agg.progress_buckets[bucketProgress(g.progress)] += 1;

      const key = `${tid}:${g.user_id}`;
      if (!memberHasGoal.has(key)) memberHasGoal.add(key);
      if (!goalsByTeam.has(tid)) goalsByTeam.set(tid, []);
      goalsByTeam.get(tid).push(g);
    }
    for (const k of memberHasGoal.values()) {
      const [tid] = k.split(':');
      if (teamAgg.has(tid)) teamAgg.get(tid).members_with_goal += 1;
    }
    for (const [tid, list] of goalsByTeam.entries()) {
      const agg = teamAgg.get(tid);
      if (!agg) continue;
      const sum = list.reduce((s, g) => s + Number(g.progress || 0), 0);
      agg.progress_avg = list.length ? Number((sum / list.length).toFixed(2)) : 0;
    }

    const goalIds = goals.map((g) => g.id).filter(Boolean);

    const plansRaw = await q(
      `
        select ap.id, ap.goal_id, ap.status, ap.end_date, ap.evidence_link, g.user_id, u.team_id as team_id
        from action_plans ap
        join goals g on g.id = ap.goal_id
        join users u on u.id = g.user_id
        where g.year = ?
        ${teamId ? 'and u.team_id = ?' : ''}
      `,
      teamId ? [targetYear, teamId] : [targetYear]
    );

    const todayStart = new Date(now);
    todayStart.setHours(0, 0, 0, 0);

    for (const p of plansRaw || []) {
      const tid = p.team_id ?? null;
      if (!tid) continue;
      if (!teamAgg.has(tid)) teamAgg.set(tid, initTeamAgg());
      const agg = teamAgg.get(tid);
      agg.action_plans.total += 1;
      if (p.status === 'Completed') agg.action_plans.completed += 1;
      const ev = typeof p.evidence_link === 'string' ? p.evidence_link.trim() : '';
      if (p.status === 'Completed' && ev) agg.action_plans.completed_with_evidence += 1;
      if (p.end_date && p.status !== 'Completed') {
        const end = parseDateOnly(p.end_date);
        if (!Number.isNaN(end.getTime()) && end.getTime() < todayStart.getTime()) agg.action_plans.overdue += 1;
      }
    }
    for (const agg of teamAgg.values()) {
      agg.action_plans.evidence_rate =
        agg.action_plans.completed > 0 ? Number((agg.action_plans.completed_with_evidence / agg.action_plans.completed).toFixed(4)) : 0;
    }

    const reportsRows = await q(
      `
        select wr.goal_id, wr.date, g.user_id, u.team_id as team_id
        from weekly_reports wr
        join goals g on g.id = wr.goal_id
        join users u on u.id = g.user_id
        where g.year = ?
          and wr.date >= ?
          and wr.date <= ?
          ${teamId ? 'and u.team_id = ?' : ''}
      `,
      teamId ? [targetYear, fromStr, toStr, teamId] : [targetYear, fromStr, toStr]
    );

    const activeUsersThisWeekByTeam = new Map();
    const reportsByWeekByTeam = new Map();
    for (const r of reportsRows || []) {
      const uid = r.user_id ?? null;
      const tid = r.team_id ?? null;
      if (!uid || !tid) continue;
      const dateOnly = typeof r.date === 'string' ? r.date.slice(0, 10) : null;
      if (!isValidDateOnly(dateOnly)) continue;
      if (!teamAgg.has(tid)) teamAgg.set(tid, initTeamAgg());
      teamAgg.get(tid).weekly_reports.reports_in_window += 1;

      if (dateOnly >= toDateOnly(thisWeekStart)) {
        const set = activeUsersThisWeekByTeam.get(tid) || new Set();
        set.add(uid);
        activeUsersThisWeekByTeam.set(tid, set);
      }

      const wk = weekKey(parseDateOnly(dateOnly));
      if (!reportsByWeekByTeam.has(tid)) reportsByWeekByTeam.set(tid, new Map());
      const m = reportsByWeekByTeam.get(tid);
      if (!m.has(wk)) m.set(wk, new Set());
      m.get(wk).add(uid);
    }

    for (const [tid, set] of activeUsersThisWeekByTeam.entries()) {
      if (!teamAgg.has(tid)) teamAgg.set(tid, initTeamAgg());
      const agg = teamAgg.get(tid);
      agg.weekly_reports.active_members_this_week = set.size;
      agg.weekly_reports.active_rate_this_week = agg.members_total > 0 ? Number((set.size / agg.members_total).toFixed(4)) : 0;
    }

    const vrs = await q(
      `
        select vr.status, g.user_id, u.team_id as team_id
        from verification_requests vr
        join goals g on g.id = vr.goal_id
        join users u on u.id = g.user_id
        where g.year = ?
        ${teamId ? 'and u.team_id = ?' : ''}
      `,
      teamId ? [targetYear, teamId] : [targetYear]
    );

    for (const vr of vrs || []) {
      const tid = vr.team_id ?? null;
      if (!tid) continue;
      if (!teamAgg.has(tid)) teamAgg.set(tid, initTeamAgg());
      const agg = teamAgg.get(tid);
      if (vr.status === 'Reviewed') agg.verifications.reviewed += 1;
      else agg.verifications.pending += 1;
    }

    try {
      if (goalIds.length > 0) {
        const prevCutoff = new Date(thisWeekStart);
        prevCutoff.setMilliseconds(prevCutoff.getMilliseconds() - 1);
        const historyFrom = new Date(prevCutoff);
        historyFrom.setDate(historyFrom.getDate() - 14);

        const hist = await q(
          `
            select goal_id, progress, recorded_at
            from goal_progress_history
            where goal_id in (?)
              and recorded_at >= ?
              and recorded_at <= ?
            order by recorded_at desc
          `,
          [goalIds, historyFrom.toISOString(), now.toISOString()]
        );

        const cur = new Map();
        const prev = new Map();
        for (const row of hist || []) {
          const gid = row.goal_id;
          if (!gid) continue;
          const recAt = row.recorded_at ? new Date(row.recorded_at) : null;
          if (!recAt || Number.isNaN(recAt.getTime())) continue;
          const p = Number(row.progress || 0);
          if (!cur.has(gid)) cur.set(gid, p);
          if (!prev.has(gid) && recAt.getTime() <= prevCutoff.getTime()) prev.set(gid, p);
          if (cur.size === goalIds.length && prev.size === goalIds.length) break;
        }

        const deltaSumByTeam = new Map();
        const deltaCountByTeam = new Map();
        for (const g of goals) {
          const tid = g.team_id;
          if (!tid) continue;
          const curP = cur.has(g.id) ? cur.get(g.id) : g.progress;
          const prevP = prev.has(g.id) ? prev.get(g.id) : curP;
          const d = Number(curP) - Number(prevP);
          deltaSumByTeam.set(tid, (deltaSumByTeam.get(tid) || 0) + d);
          deltaCountByTeam.set(tid, (deltaCountByTeam.get(tid) || 0) + 1);
        }
        for (const [tid, sum] of deltaSumByTeam.entries()) {
          const cnt = deltaCountByTeam.get(tid) || 0;
          if (!teamAgg.has(tid)) teamAgg.set(tid, initTeamAgg());
          teamAgg.get(tid).progress_delta = cnt ? Number((sum / cnt).toFixed(2)) : 0;
        }
      }
    } catch {
      // ignore
    }

    const weeksSeries = [];
    for (let i = lookbackWeeks - 1; i >= 0; i--) {
      const d = new Date(thisWeekStart);
      d.setDate(d.getDate() - i * 7);
      const wk = weekKey(d);
      if (teamId) {
        const m = reportsByWeekByTeam.get(teamId) || new Map();
        const set = m.get(wk) || new Set();
        const mt = teamAgg.get(teamId)?.members_total || 0;
        weeksSeries.push({ week: wk, active_members: set.size, active_rate: mt > 0 ? Number((set.size / mt).toFixed(4)) : 0 });
      } else {
        let active = 0;
        let totalMembers = 0;
        for (const [tid, agg] of teamAgg.entries()) {
          totalMembers += agg.members_total || 0;
          const m = reportsByWeekByTeam.get(tid) || new Map();
          const set = m.get(wk) || new Set();
          active += set.size;
        }
        weeksSeries.push({ week: wk, active_members: active, active_rate: totalMembers > 0 ? Number((active / totalMembers).toFixed(4)) : 0 });
      }
    }

    const perTeam = (teams || [])
      .filter((t) => (teamId ? t.id === teamId : true))
      .map((t) => ({ team_id: t.id, team_name: t.name, ...teamAgg.get(t.id) }));

    const org = initTeamAgg();
    let orgProgressSum = 0;
    let orgGoalsCount = 0;
    for (const row of perTeam) {
      org.members_total += row.members_total || 0;
      org.members_with_goal += row.members_with_goal || 0;
      org.goals_total += row.goals_total || 0;
      org.goals_review.approved += row.goals_review?.approved || 0;
      org.goals_review.pending += row.goals_review?.pending || 0;
      org.action_plans.total += row.action_plans?.total || 0;
      org.action_plans.overdue += row.action_plans?.overdue || 0;
      org.action_plans.completed += row.action_plans?.completed || 0;
      org.action_plans.completed_with_evidence += row.action_plans?.completed_with_evidence || 0;
      org.weekly_reports.reports_in_window += row.weekly_reports?.reports_in_window || 0;
      org.weekly_reports.active_members_this_week += row.weekly_reports?.active_members_this_week || 0;
      org.verifications.pending += row.verifications?.pending || 0;
      org.verifications.reviewed += row.verifications?.reviewed || 0;
      org.progress_buckets['0_24'] += row.progress_buckets?.['0_24'] || 0;
      org.progress_buckets['25_49'] += row.progress_buckets?.['25_49'] || 0;
      org.progress_buckets['50_74'] += row.progress_buckets?.['50_74'] || 0;
      org.progress_buckets['75_99'] += row.progress_buckets?.['75_99'] || 0;
      org.progress_buckets['100'] += row.progress_buckets?.['100'] || 0;
      orgProgressSum += (row.progress_avg || 0) * (row.goals_total || 0);
      orgGoalsCount += row.goals_total || 0;
    }
    org.progress_avg = orgGoalsCount ? Number((orgProgressSum / orgGoalsCount).toFixed(2)) : 0;
    org.action_plans.evidence_rate =
      org.action_plans.completed > 0 ? Number((org.action_plans.completed_with_evidence / org.action_plans.completed).toFixed(4)) : 0;
    org.weekly_reports.active_rate_this_week =
      org.members_total > 0 ? Number((org.weekly_reports.active_members_this_week / org.members_total).toFixed(4)) : 0;

    if (LOG_TIMINGS) {
      const ms = nowMs() - t0;
      console.log('[DB]', `GET /manager/overview (mysql) (${ms.toFixed(1)}ms) goals=${goals.length} reports=${(reportsRows || []).length}`);
    }

    res.json({
      data: {
        year: targetYear,
        team_id: teamId,
        window: { from: fromStr, to: toStr, weeks: lookbackWeeks },
        org,
        per_team: perTeam,
        trends: { weeks: weeksSeries },
      },
    });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.get('/manager/team-members/summary', verifyCognito, requireManager, async (req, res) => {
  const { year, team_id, weeks } = req.query;
  const targetYear = Number(year);
  if (!targetYear || Number.isNaN(targetYear)) return res.status(400).json({ error: 'Query param "year" is required (number)' });
  const teamId = typeof team_id === 'string' && team_id.trim() ? team_id.trim() : null;
  if (!teamId) return res.status(400).json({ error: 'Query param "team_id" is required' });

  const lookbackWeeks = Math.max(1, Math.min(26, Number(weeks || 8)));
  const now = new Date();
  const thisWeekStart = startOfWeekMonday(now);
  const from = new Date(thisWeekStart);
  from.setDate(from.getDate() - (lookbackWeeks - 1) * 7);
  const fromStr = toDateOnly(from);
  const toStr = toDateOnly(now);

  const t0 = LOG_TIMINGS ? nowMs() : 0;

  const users = await q(
    `
      select u.id, u.email, u.name, u.team_id, t.name as team_name
      from users u
      left join teams t on t.id = u.team_id
      where u.team_id = ?
      order by u.name asc, u.email asc
    `,
    [teamId]
  );
  const memberIds = (users || []).map((u) => u.id).filter(Boolean);
  const teamName = users?.[0]?.team_name ?? null;
  if (memberIds.length === 0) {
    return res.json({
      data: { year: targetYear, team_id: teamId, team_name: teamName, window: { from: fromStr, to: toStr, weeks: lookbackWeeks }, members: [], top: { progress_delta: [], evidence_rate: [], overdue_plans: [], activity_streak: [] } },
    });
  }

  const members = new Map();
  for (const u of users || []) {
    members.set(u.id, {
      user_id: u.id,
      name: u.name ?? null,
      email: u.email ?? null,
      team_id: teamId,
      team_name: teamName,
      goals: { total: 0, approved: 0, pending: 0, progress_avg: 0, progress_sum: 0 },
      progress_delta: null,
      action_plans: { total: 0, overdue: 0, completed: 0, completed_with_evidence: 0, evidence_rate: 0 },
      weekly_reports: { reports_in_window: 0, weeks_with_activity: 0, streak_weeks: 0 },
      verifications: { pending: 0, reviewed: 0 },
    });
  }

  const goals = await q(`select id, user_id, progress, review_status from goals where year = ? and user_id in (?)`, [targetYear, memberIds]);
  const goalIds = (goals || []).map((g) => g.id).filter(Boolean);
  for (const g of goals || []) {
    const m = members.get(g.user_id);
    if (!m) continue;
    m.goals.total += 1;
    const rs = g.review_status || null;
    if (rs === 'Approved') m.goals.approved += 1;
    if (!rs || rs === 'Pending') m.goals.pending += 1;
    const p = Number(g.progress || 0);
    m.goals.progress_sum += p;
  }
  for (const m of members.values()) {
    m.goals.progress_avg = m.goals.total ? Number((m.goals.progress_sum / m.goals.total).toFixed(2)) : 0;
  }

  const plans = await q(
    `
      select ap.id, ap.goal_id, ap.status, ap.end_date, ap.evidence_link, g.user_id
      from action_plans ap
      join goals g on g.id = ap.goal_id
      where g.year = ?
        and g.user_id in (?)
    `,
    [targetYear, memberIds]
  );

  const todayStart = new Date(now);
  todayStart.setHours(0, 0, 0, 0);
  for (const p of plans || []) {
    const uid = p.user_id ?? null;
    const m = uid ? members.get(uid) : null;
    if (!m) continue;
    m.action_plans.total += 1;
    if (p.status === 'Completed') m.action_plans.completed += 1;
    const ev = typeof p.evidence_link === 'string' ? p.evidence_link.trim() : '';
    if (p.status === 'Completed' && ev) m.action_plans.completed_with_evidence += 1;
    if (p.end_date && p.status !== 'Completed') {
      const end = parseDateOnly(p.end_date);
      if (!Number.isNaN(end.getTime()) && end.getTime() < todayStart.getTime()) m.action_plans.overdue += 1;
    }
  }
  for (const m of members.values()) {
    m.action_plans.evidence_rate = m.action_plans.completed > 0 ? Number((m.action_plans.completed_with_evidence / m.action_plans.completed).toFixed(4)) : 0;
  }

  const reports = await q(
    `
      select wr.goal_id, wr.date, g.user_id
      from weekly_reports wr
      join goals g on g.id = wr.goal_id
      where g.year = ?
        and g.user_id in (?)
        and wr.date >= ?
        and wr.date <= ?
    `,
    [targetYear, memberIds, fromStr, toStr]
  );
  const weeksWithActivityByUser = new Map();
  for (const r of reports || []) {
    const uid = r.user_id ?? null;
    if (!uid) continue;
    const m = members.get(uid);
    if (!m) continue;
    m.weekly_reports.reports_in_window += 1;
    const dateOnly = typeof r.date === 'string' ? r.date.slice(0, 10) : null;
    if (!isValidDateOnly(dateOnly)) continue;
    const wk = weekKey(parseDateOnly(dateOnly));
    if (!weeksWithActivityByUser.has(uid)) weeksWithActivityByUser.set(uid, new Set());
    weeksWithActivityByUser.get(uid).add(wk);
  }

  for (const [uid, set] of weeksWithActivityByUser.entries()) {
    const m = members.get(uid);
    if (!m) continue;
    m.weekly_reports.weeks_with_activity = set.size;
    let streakWeeks = 0;
    for (let i = 0; i < lookbackWeeks; i++) {
      const d = new Date(thisWeekStart);
      d.setDate(d.getDate() - i * 7);
      if (set.has(weekKey(d))) streakWeeks += 1;
      else break;
    }
    m.weekly_reports.streak_weeks = streakWeeks;
  }

  const vrs = await q(
    `
      select vr.status, vr.requester_id
      from verification_requests vr
      join goals g on g.id = vr.goal_id
      where g.year = ?
        and vr.requester_id in (?)
    `,
    [targetYear, memberIds]
  );
  for (const vr of vrs || []) {
    const m = members.get(vr.requester_id);
    if (!m) continue;
    if (vr.status === 'Reviewed') m.verifications.reviewed += 1;
    else m.verifications.pending += 1;
  }

  try {
    if (goalIds.length > 0) {
      const prevCutoff = new Date(thisWeekStart);
      prevCutoff.setMilliseconds(prevCutoff.getMilliseconds() - 1);
      const historyFrom = new Date(prevCutoff);
      historyFrom.setDate(historyFrom.getDate() - 14);
      const hist = await q(
        `
          select goal_id, progress, recorded_at
          from goal_progress_history
          where goal_id in (?)
            and recorded_at >= ?
            and recorded_at <= ?
          order by recorded_at desc
        `,
        [goalIds, historyFrom.toISOString(), now.toISOString()]
      );
      const cur = new Map();
      const prev = new Map();
      for (const row of hist || []) {
        const gid = row.goal_id;
        if (!gid) continue;
        const recAt = row.recorded_at ? new Date(row.recorded_at) : null;
        if (!recAt || Number.isNaN(recAt.getTime())) continue;
        const p = Number(row.progress || 0);
        if (!cur.has(gid)) cur.set(gid, p);
        if (!prev.has(gid) && recAt.getTime() <= prevCutoff.getTime()) prev.set(gid, p);
      }
      const goalById = new Map((goals || []).map((g) => [g.id, g]));
      const sumByUser = new Map();
      const cntByUser = new Map();
      for (const gid of goalIds) {
        const g = goalById.get(gid);
        if (!g) continue;
        const uid = g.user_id;
        const curP = cur.has(gid) ? cur.get(gid) : Number(g.progress || 0);
        const prevP = prev.has(gid) ? prev.get(gid) : curP;
        const d = Number(curP) - Number(prevP);
        sumByUser.set(uid, (sumByUser.get(uid) || 0) + d);
        cntByUser.set(uid, (cntByUser.get(uid) || 0) + 1);
      }
      for (const [uid, sum] of sumByUser.entries()) {
        const cnt = cntByUser.get(uid) || 0;
        const m = members.get(uid);
        if (!m) continue;
        m.progress_delta = cnt ? Number((sum / cnt).toFixed(2)) : 0;
      }
    }
  } catch {
    // ignore
  }

  const list = Array.from(members.values());
  const topN = (arr, keyFn, desc = true, n = 5) =>
    [...arr]
      .sort((a, b) => {
        const av = keyFn(a);
        const bv = keyFn(b);
        const ax = typeof av === 'number' ? av : -Infinity;
        const bx = typeof bv === 'number' ? bv : -Infinity;
        return desc ? bx - ax : ax - bx;
      })
      .slice(0, n);

  if (LOG_TIMINGS) {
    const ms = nowMs() - t0;
    console.log('[DB]', `GET /manager/team-members/summary (mysql) (${ms.toFixed(1)}ms) users=${memberIds.length} goals=${goalIds.length}`);
  }

  res.json({
    data: {
      year: targetYear,
      team_id: teamId,
      team_name: teamName,
      window: { from: fromStr, to: toStr, weeks: lookbackWeeks },
      members: list,
      top: {
        progress_delta: topN(list, (m) => (typeof m.progress_delta === 'number' ? m.progress_delta : -Infinity), true),
        evidence_rate: topN(list, (m) => m.action_plans.evidence_rate, true),
        overdue_plans: topN(list, (m) => m.action_plans.overdue, true),
        activity_streak: topN(list, (m) => m.weekly_reports.streak_weeks, true),
      },
      bottom: {
        progress_delta: topN(list, (m) => (typeof m.progress_delta === 'number' ? m.progress_delta : Infinity), false),
      },
    },
  });
});

app.get('/manager/team-members/trends', verifyCognito, requireManager, async (req, res) => {
  const { year, team_id, weeks } = req.query;
  const targetYear = Number(year);
  if (!targetYear || Number.isNaN(targetYear)) return res.status(400).json({ error: 'Query param "year" is required (number)' });
  const teamId = typeof team_id === 'string' && team_id.trim() ? team_id.trim() : null;
  if (!teamId) return res.status(400).json({ error: 'Query param "team_id" is required' });

  const lookbackWeeks = Math.max(1, Math.min(26, Number(weeks || 8)));
  const now = new Date();
  const thisWeekStart = startOfWeekMonday(now);
  const from = new Date(thisWeekStart);
  from.setDate(from.getDate() - (lookbackWeeks - 1) * 7);
  const fromStr = toDateOnly(from);
  const toStr = toDateOnly(now);

  const weeksAxis = [];
  for (let i = lookbackWeeks - 1; i >= 0; i--) {
    const d = new Date(thisWeekStart);
    d.setDate(d.getDate() - i * 7);
    weeksAxis.push(weekKey(d));
  }
  const weekIndex = new Map(weeksAxis.map((w, i) => [w, i]));

  const users = await q(
    `
      select u.id, u.email, u.name, u.team_id, t.name as team_name
      from users u
      left join teams t on t.id = u.team_id
      where u.team_id = ?
      order by u.name asc, u.email asc
    `,
    [teamId]
  );
  const memberIds = (users || []).map((u) => u.id).filter(Boolean);
  const teamName = users?.[0]?.team_name ?? null;

  if (memberIds.length === 0) {
    return res.json({ data: { year: targetYear, team_id: teamId, team_name: teamName, window: { from: fromStr, to: toStr, weeks: lookbackWeeks }, weeks: weeksAxis, members: [] } });
  }

  const seriesByUser = new Map();
  for (const u of users || []) {
    seriesByUser.set(u.id, { user_id: u.id, name: u.name ?? null, email: u.email ?? null, reports_by_week: Array(weeksAxis.length).fill(0) });
  }

  for (const batch of chunk(memberIds, 200)) {
    const rows = await q(
      `
        select wr.date, g.user_id
        from weekly_reports wr
        join goals g on g.id = wr.goal_id
        where g.year = ?
          and g.user_id in (?)
          and wr.date >= ?
          and wr.date <= ?
      `,
      [targetYear, batch, fromStr, toStr]
    );
    for (const r of rows || []) {
      const uid = r.user_id ?? null;
      if (!uid) continue;
      const dateOnly = typeof r.date === 'string' ? r.date.slice(0, 10) : null;
      if (!isValidDateOnly(dateOnly)) continue;
      const wk = weekKey(parseDateOnly(dateOnly));
      const idx = weekIndex.get(wk);
      if (typeof idx !== 'number') continue;
      const s = seriesByUser.get(uid);
      if (!s) continue;
      s.reports_by_week[idx] += 1;
    }
  }

  res.json({
    data: {
      year: targetYear,
      team_id: teamId,
      team_name: teamName,
      window: { from: fromStr, to: toStr, weeks: lookbackWeeks },
      weeks: weeksAxis,
      members: Array.from(seriesByUser.values()),
    },
  });
});

// --- Leader insights: weekly report stats per action plan for a date range ---
app.get('/leader/action-plans/weekly-report-stats', verifyCognito, requireLeader, async (req, res) => {
  const { year, user_id, from, to } = req.query;
  const fromStr = typeof from === 'string' ? from.slice(0, 10) : null;
  const toStr = typeof to === 'string' ? to.slice(0, 10) : null;
  if (!isValidDateOnly(fromStr) || !isValidDateOnly(toStr)) return res.status(400).json({ error: 'Query params "from" and "to" (YYYY-MM-DD) are required' });

  const targetYear = typeof year !== 'undefined' && year !== null && `${year}`.trim() !== '' ? Number(year) : null;
  if (targetYear == null || Number.isNaN(targetYear)) return res.status(400).json({ error: 'Query param "year" is required' });

  const scope = await getLeaderTeamScope(req);
  if (!scope.ok) return res.status(scope.status).json({ message: scope.message });

  if (typeof user_id === 'string' && user_id.trim()) {
    const u = await q1(`select id, team_id from users where id = ? limit 1`, [user_id.trim()]);
    if (!u) return res.status(404).json({ message: 'User not found' });
    if (u.team_id !== scope.teamId) return res.status(403).json({ message: 'Forbidden (team scope)' });
  }

  const t0 = LOG_TIMINGS ? nowMs() : 0;
  try {
    const params = [fromStr, toStr, targetYear, scope.teamId];
    let whereUser = '';
    if (typeof user_id === 'string' && user_id.trim()) {
      whereUser = 'and g.user_id = ?';
      params.push(user_id.trim());
    }

    const rows = await q(
      `
        select
          ap.id as action_plan_id,
          max(wr.date) as last_report_date,
          max(case when wr.date >= ? and wr.date <= ? then 1 else 0 end) as has_report_in_range
        from action_plans ap
        join goals g on g.id = ap.goal_id
        join users u on u.id = g.user_id
        left join weekly_reports wr on wr.action_plan_id = ap.id
        where ap.status in ('In Progress', 'Blocked')
          and g.status = 'In Progress'
          and g.year = ?
          and u.team_id = ?
          ${whereUser}
        group by ap.id
      `,
      params
    );

    const stats = {};
    for (const r of rows || []) {
      stats[r.action_plan_id] = {
        lastReportDate: r.last_report_date ? `${r.last_report_date}`.slice(0, 10) : null,
        hasReportInRange: Boolean(r.has_report_in_range),
      };
    }

    if (LOG_TIMINGS) {
      const ms = nowMs() - t0;
      console.log('[DB]', `GET /leader/action-plans/weekly-report-stats mysql (${ms.toFixed(1)}ms) plans=${Array.isArray(rows) ? rows.length : 0}`);
    }

    res.json({
      data: stats,
      meta: { year: targetYear, user_id: typeof user_id === 'string' && user_id.trim() ? user_id.trim() : null, from: fromStr, to: toStr, plans: Array.isArray(rows) ? rows.length : 0 },
    });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

// --- Leader update / review endpoints ---

app.put('/leader/goals/:id', verifyCognito, requireLeader, async (req, res) => {
  const { id } = req.params;
  try {
    const upd = buildUpdate('goals', req.body || {}, 'where id = ?', [id]);
    await q(upd.sql, upd.params);
    const data = hydrateRow(await q1(`select * from goals where id = ? limit 1`, [id]));
    if (!data) return res.status(404).json({ message: 'Goal not found' });
  res.json({ data });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

async function getReviewerIdentity(req) {
  const reviewerId = req.user?.sub ?? null;
  if (!reviewerId) return { id: null, email: null, name: null };
  try {
    const data = await q1(`select id, email, name from users where id = ? limit 1`, [reviewerId]);
    return { id: reviewerId, email: data?.email ?? null, name: data?.name ?? null };
  } catch {
    return { id: reviewerId, email: null, name: null };
  }
}

function isMissingColumnError(err) {
  const msg = (err?.message || '').toLowerCase();
  return err?.code === 'ER_BAD_FIELD_ERROR' || msg.includes('unknown column');
}

app.put('/leader/goals/:id/review', verifyCognito, requireLeader, async (req, res) => {
  const { id } = req.params;
  const { status, comment } = req.body || {};
  const lock = status === 'Approved' ? true : status === 'Rejected' || status === 'Cancelled' ? false : true;

  try {
    const existing = await q1(`select id, status from goals where id = ? limit 1`, [id]);
    if (!existing) return res.status(404).json({ message: 'Goal not found' });

    const nextStatus = status === 'Approved' && (existing.status === 'Not started' || existing.status === 'Draft') ? 'In Progress' : existing.status;
    const nowIso = new Date().toISOString();
    const reviewer = await getReviewerIdentity(req);

    const baseUpdate = { review_status: status, leader_review_notes: comment, is_locked: lock ? 1 : 0, status: nextStatus };
    const auditUpdate = {
      ...baseUpdate,
      reviewed_by: reviewer.id,
      reviewed_by_email: reviewer.email,
      reviewed_by_name: reviewer.name,
      reviewed_at: nowIso,
      approved_at: status === 'Approved' ? nowIso : null,
      rejected_at: status === 'Rejected' ? nowIso : null,
    };

    try {
      const upd = buildUpdate('goals', auditUpdate, 'where id = ?', [id]);
      await q(upd.sql, upd.params);
    } catch (e) {
      if (isMissingColumnError(e)) {
        const upd = buildUpdate('goals', baseUpdate, 'where id = ?', [id]);
        await q(upd.sql, upd.params);
      } else {
        throw e;
      }
    }

  res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.put('/leader/action-plans/:id/review', verifyCognito, requireLeader, async (req, res) => {
  const { id } = req.params;
  const { status, comment } = req.body || {};
  const lock = status === 'Pending';

  try {
    const plan = await q1(`select id, request_deadline_date from action_plans where id = ? limit 1`, [id]);
    if (!plan) return res.status(404).json({ message: 'Action plan not found' });

    const updatePayload = { review_status: status, leader_review_notes: comment, is_locked: lock ? 1 : 0 };
  if (status === 'Approved' && plan.request_deadline_date) {
    updatePayload.end_date = plan.request_deadline_date;
    updatePayload.request_deadline_date = null;
  }
    if (status === 'Rejected') updatePayload.request_deadline_date = null;

    const nowIso = new Date().toISOString();
    const reviewer = await getReviewerIdentity(req);
    const baseUpdate = updatePayload;
    const auditUpdate = {
      ...baseUpdate,
      reviewed_by: reviewer.id,
      reviewed_by_email: reviewer.email,
      reviewed_by_name: reviewer.name,
      reviewed_at: nowIso,
      approved_at: status === 'Approved' ? nowIso : null,
      rejected_at: status === 'Rejected' ? nowIso : null,
    };

    try {
      const upd = buildUpdate('action_plans', auditUpdate, 'where id = ?', [id]);
      await q(upd.sql, upd.params);
    } catch (e) {
      if (isMissingColumnError(e)) {
        const upd = buildUpdate('action_plans', baseUpdate, 'where id = ?', [id]);
        await q(upd.sql, upd.params);
      } else {
        throw e;
      }
    }

  res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

// --- Verifications (member submit, leader review) ---

app.get('/verification-templates', verifyCognito, async (req, res) => {
  try {
    const rows = hydrateRows(await q(`select id, name, category, scoring_type, criteria, required_evidence, minimum_bar from verification_templates order by name asc`, []));
    res.json({ data: rows || [] });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.post('/verification-templates', verifyCognito, requireLeader, async (req, res) => {
  const leaderId = req.user.sub;
  const { name, category, scoring_type, criteria, required_evidence, minimum_bar } = req.body || {};
  if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name is required' });

  const payload = {
    id: crypto.randomUUID(),
    name: name.trim(),
    category: typeof category === 'string' ? category.trim() : null,
    scoring_type: typeof scoring_type === 'string' ? scoring_type : 'rubric',
    criteria: Array.isArray(criteria) ? criteria : [],
    required_evidence: Array.isArray(required_evidence) ? required_evidence : [],
    minimum_bar: minimum_bar && typeof minimum_bar === 'object' ? minimum_bar : null,
    created_by: leaderId,
  };

  try {
    const ins = buildInsert('verification_templates', payload);
    await q(ins.sql, ins.params);
    const data = hydrateRow(await q1(`select * from verification_templates where id = ? limit 1`, [payload.id]));
    res.json({ data: data || null });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.post('/verification-requests', verifyCognito, async (req, res) => {
  const requesterId = req.user.sub;
  const { goal_id, action_plan_id, template_id, scope, evidence_links, rubric_snapshot, member_notes } = req.body || {};
  if (!goal_id || typeof goal_id !== 'string') return res.status(400).json({ error: 'goal_id is required' });
  if (!scope || typeof scope !== 'string') return res.status(400).json({ error: 'scope is required' });

  const access = await assertCanAccessGoal(req, goal_id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  const payload = {
    id: crypto.randomUUID(),
    requester_id: requesterId,
    goal_id,
    action_plan_id: typeof action_plan_id === 'string' && action_plan_id.trim() ? action_plan_id.trim() : null,
    template_id: typeof template_id === 'string' && template_id.trim() ? template_id.trim() : null,
    scope: scope.trim(),
    evidence_links: Array.isArray(evidence_links) ? evidence_links : [],
    rubric_snapshot: rubric_snapshot && typeof rubric_snapshot === 'object' ? rubric_snapshot : {},
    member_notes: typeof member_notes === 'string' ? member_notes : null,
    status: 'Pending',
  };

  try {
    const ins = buildInsert('verification_requests', payload);
    await q(ins.sql, ins.params);
    const data = hydrateRow(await q1(`select * from verification_requests where id = ? limit 1`, [payload.id]));
    res.json({ data: data || null });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.get('/verification-requests', verifyCognito, async (req, res) => {
  const isLeader = isLeaderUser(req);
  const me = req.user.sub;
  const { year, status, user_id, team_id, limit, offset } = req.query;
  const pageLimit = Math.max(1, Math.min(200, Number(limit || 50)));
  const pageOffset = Math.max(0, Number(offset || 0));

  try {
    let scope = null;
    if (isLeader) {
      scope = await getLeaderTeamScope(req);
      if (!scope.ok) return res.status(scope.status).json({ message: scope.message });
      if (typeof team_id === 'string' && team_id.trim() && team_id.trim() !== scope.teamId) return res.status(403).json({ message: 'Forbidden (team scope)' });
    }

    const params = [];
    let where = 'where 1=1';

    if (!isLeader) {
      where += ' and vr.requester_id = ?';
      params.push(me);
    } else {
      where += ' and u.team_id = ?';
      params.push(scope.teamId);
      if (typeof user_id === 'string' && user_id.trim()) {
        where += ' and vr.requester_id = ?';
        params.push(user_id.trim());
      }
    }

    if (typeof year !== 'undefined' && `${year}`.trim() !== '') {
      where += ' and g.year = ?';
      params.push(Number(year));
    }
    if (typeof status === 'string' && status.trim()) {
      where += ' and vr.status = ?';
      params.push(status.trim());
    }

    const rows = await q(
      `
        select
          vr.id,
          vr.requester_id,
          vr.goal_id,
          vr.action_plan_id,
          vr.template_id,
          vr.scope,
          vr.evidence_links,
          vr.status,
          vr.created_at,
          vr.updated_at,
          g.id as goal_ref_id,
          g.name as goal_name,
          g.year as goal_year,
          g.user_id as goal_user_id,
          u.id as member_id,
          u.name as member_name,
          u.email as member_email,
          u.team_id as member_team_id,
          t.name as member_team_name
        from verification_requests vr
        join goals g on g.id = vr.goal_id
        join users u on u.id = vr.requester_id
        left join teams t on t.id = u.team_id
        ${where}
        order by vr.created_at desc
        limit ?
        offset ?
      `,
      [...params, pageLimit, pageOffset]
    );

    const shaped = hydrateRows(rows || []).map((r) => ({
      id: r.id,
      requester_id: r.requester_id,
      goal_id: r.goal_id,
      action_plan_id: r.action_plan_id,
      template_id: r.template_id,
      scope: r.scope,
      evidence_links: r.evidence_links,
      status: r.status,
      created_at: r.created_at,
      updated_at: r.updated_at,
      member_name: r.member_name ?? null,
      member_email: r.member_email ?? null,
      team_id: r.member_team_id ?? null,
      team_name: r.member_team_name ?? null,
      goal: { id: r.goal_ref_id, name: r.goal_name, year: r.goal_year, user_id: r.goal_user_id },
    }));

    res.json({ data: shaped, page: { limit: pageLimit, offset: pageOffset, returned: shaped.length } });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.get('/verification-requests/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const isLeader = isLeaderUser(req);
  const me = req.user.sub;

  try {
    const data = hydrateRow(
      await q1(
        `
          select
            vr.*,
            g.id as goal_ref_id,
            g.name as goal_name,
            g.year as goal_year,
            g.user_id as goal_user_id,
            u.id as member_id,
            u.name as member_name,
            u.email as member_email,
            u.team_id as member_team_id,
            t.name as member_team_name
          from verification_requests vr
          join goals g on g.id = vr.goal_id
          join users u on u.id = vr.requester_id
          left join teams t on t.id = u.team_id
          where vr.id = ?
          limit 1
        `,
        [id]
      )
    );
    if (!data) return res.status(404).json({ error: 'Not found' });

    if (!isLeader && data.requester_id !== me) return res.status(403).json({ message: 'Forbidden' });
    if (isLeader) {
      const scope = await getLeaderTeamScope(req);
      if (!scope.ok) return res.status(scope.status).json({ message: scope.message });
      if (data.member_team_id !== scope.teamId) return res.status(403).json({ message: 'Forbidden (team scope)' });
    }

    const reviews = hydrateRows(await q(`select * from verification_reviews where request_id = ? order by reviewed_at desc`, [data.id]));
    const shaped = {
      ...data,
      verification_reviews: reviews || [],
      member_name: data.member_name ?? null,
      member_email: data.member_email ?? null,
      team_id: data.member_team_id ?? null,
      team_name: data.member_team_name ?? null,
      goal: { id: data.goal_ref_id, name: data.goal_name, year: data.goal_year, user_id: data.goal_user_id },
    };
    delete shaped.goal_ref_id;
    delete shaped.goal_name;
    delete shaped.goal_year;
    delete shaped.goal_user_id;
    delete shaped.member_id;
    delete shaped.member_team_id;
    delete shaped.member_team_name;

    res.json({ data: shaped });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

app.post('/verification-requests/:id/review', verifyCognito, requireLeader, async (req, res) => {
  const { id } = req.params;
  const leaderId = req.user.sub;
  const { result, scores, leader_feedback } = req.body || {};
  if (!result || !['Pass', 'NeedsWork', 'Fail'].includes(result)) return res.status(400).json({ error: 'result must be Pass/NeedsWork/Fail' });

  try {
    const vr = await q1(
      `
        select vr.id, vr.requester_id, vr.status, u.team_id as team_id
        from verification_requests vr
        join users u on u.id = vr.requester_id
        where vr.id = ?
        limit 1
      `,
      [id]
    );
    if (!vr) return res.status(404).json({ error: 'Not found' });

    const scope = await getLeaderTeamScope(req);
    if (!scope.ok) return res.status(scope.status).json({ message: scope.message });
    if (vr.team_id !== scope.teamId) return res.status(403).json({ message: 'Forbidden (team scope)' });

    const reviewPayload = {
      request_id: vr.id,
      leader_id: leaderId,
      result,
      scores: scores && typeof scores === 'object' ? scores : {},
      leader_feedback: typeof leader_feedback === 'string' ? leader_feedback : null,
      reviewed_at: new Date().toISOString(),
    };

    // Upsert by request_id (requires UNIQUE KEY on request_id)
    await q(
      `
        insert into verification_reviews (request_id, leader_id, result, scores, leader_feedback, reviewed_at)
        values (?, ?, ?, ?, ?, ?)
        on duplicate key update
          leader_id = values(leader_id),
          result = values(result),
          scores = values(scores),
          leader_feedback = values(leader_feedback),
          reviewed_at = values(reviewed_at)
      `,
      [
        reviewPayload.request_id,
        reviewPayload.leader_id,
        reviewPayload.result,
        normalizeDbValue(reviewPayload.scores),
        reviewPayload.leader_feedback,
        reviewPayload.reviewed_at,
      ]
    );

    await q(`update verification_requests set status = ?, updated_at = ? where id = ?`, ['Reviewed', new Date().toISOString(), vr.id]);

    const review = hydrateRow(await q1(`select * from verification_reviews where request_id = ? limit 1`, [vr.id]));
    res.json({ data: { review: review || null } });
  } catch (e) {
    res.status(500).json({ error: e instanceof Error ? e.message : String(e) });
  }
});


const PORT = Number(process.env.PORT || 3002);
app.listen(PORT, () => {
  console.log(`Goal MySQL v1 running on http://localhost:${PORT}`);
});


