import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import supabase from './config/supabaseClient.js';
import { verifyCognito, requireLeader, requireManager } from './middleware/verifyCognito.js';

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Health check (no auth) — use this to verify Nginx → Node path quickly.
// Example from EC2: curl -i http://localhost:3000/healthz
app.get('/healthz', (req, res) => {
  res.json({
    ok: true,
    service: 'idp-okr-backend',
    ts: new Date().toISOString(),
  });
});

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

function isLeaderUser(req) {
  const groups = req.user?.['cognito:groups'];
  const groupList = Array.isArray(groups)
    ? groups
    : typeof groups === 'string'
      ? [groups]
      : [];
  return groupList.includes('leader');
}

// --- Manager APIs (org-wide read-only dashboard) ---

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

function bucketProgress(p) {
  const x = Math.max(0, Math.min(100, Number(p || 0)));
  if (x < 25) return '0_24';
  if (x < 50) return '25_49';
  if (x < 75) return '50_74';
  if (x < 100) return '75_99';
  return '100';
}

// GET /manager/teams (org-wide)
app.get('/manager/teams', verifyCognito, requireManager, async (req, res) => {
  const { data, error } = await supabase.from('teams').select('id, name').order('name', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data || [] });
});

// GET /manager/users?team_id=<uuid>&limit=500&offset=0
app.get('/manager/users', verifyCognito, requireManager, async (req, res) => {
  const { team_id, limit, offset } = req.query;
  const pageLimit = Math.max(1, Math.min(1000, Number(limit || 500)));
  const pageOffset = Math.max(0, Number(offset || 0));

  let q = supabase
    .from('users')
    .select(
      `
      id,
      email,
      name,
      team_id,
      role,
      teams (
        id,
        name
      )
    `
    )
    .order('name', { ascending: true })
    .range(pageOffset, pageOffset + pageLimit - 1);

  if (typeof team_id === 'string' && team_id.trim()) {
    q = q.eq('team_id', team_id.trim());
  }

  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });

  const shaped =
    (data || []).map((u) => ({
      id: u.id,
      email: u.email ?? null,
      name: u.name ?? null,
      team_id: u.team_id ?? null,
      team_name: u.teams?.name ?? null,
      role: u.role ?? null,
    })) || [];

  res.json({
    data: shaped,
    page: { limit: pageLimit, offset: pageOffset, returned: Array.isArray(data) ? data.length : 0 },
  });
});

// GET /manager/member-insights?year=2025&user_id=<uuid>&weeks=8
// Same output as leader member-insights, but org-wide (no team scope).
app.get('/manager/member-insights', verifyCognito, requireManager, async (req, res) => {
  const { year, user_id, weeks } = req.query;
  const targetYear = Number(year);
  if (!targetYear || Number.isNaN(targetYear)) {
    return res.status(400).json({ error: 'Query param "year" is required (number)' });
  }
  if (typeof user_id !== 'string' || !user_id.trim()) {
    return res.status(400).json({ error: 'Query param "user_id" is required' });
  }

  const userId = user_id.trim();
  const lookbackWeeks = Math.max(1, Math.min(26, Number(weeks || 8)));

  const now = new Date();
  const thisWeekStart = startOfWeekMonday(now);
  const from = new Date(thisWeekStart);
  from.setDate(from.getDate() - (lookbackWeeks - 1) * 7);
  const fromStr = toDateOnly(from);
  const toStr = toDateOnly(now);

  // 1) Goals for member/year
  const { data: goals, error: goalsErr } = await supabase
    .from('goals')
    .select('id, user_id, year, progress, status, review_status, start_date, time_bound, updated_at')
    .eq('user_id', userId)
    .eq('year', targetYear);
  if (goalsErr) return res.status(500).json({ error: goalsErr.message });

  const goalIds = (goals || []).map((g) => g.id).filter(Boolean);
  const goalProgressById = new Map((goals || []).map((g) => [g.id, Number(g.progress || 0)]));

  // 2) Action plans for member/year (join via goals)
  const { data: plans, error: plansErr } = await supabase
    .from('action_plans')
    .select(
      `
      id,
      goal_id,
      status,
      start_date,
      end_date,
      evidence_link,
      goals!inner (
        user_id,
        year
      )
    `
    )
    .eq('goals.user_id', userId)
    .eq('goals.year', targetYear);
  if (plansErr) return res.status(500).json({ error: plansErr.message });

  // 3) Weekly reports in lookback window (via goal ids) — used for streak + blockers summary
  const reports = [];
  if (goalIds.length > 0) {
    for (const batch of chunk(goalIds, 200)) {
      const { data: rows, error: repErr } = await supabase
        .from('weekly_reports')
        .select('goal_id, action_plan_id, date, blockers_challenges')
        .in('goal_id', batch)
        .gte('date', fromStr)
        .lte('date', toStr);
      if (repErr) return res.status(500).json({ error: repErr.message });
      for (const r of rows || []) reports.push(r);
    }
  }

  // 4) Progress delta (avg progress this week vs previous week) using goal_progress_history
  let progressDelta = null;
  try {
    if (goalIds.length > 0) {
      const curCutoff = now; // now
      const prevCutoff = new Date(thisWeekStart);
      prevCutoff.setMilliseconds(prevCutoff.getMilliseconds() - 1); // just before this week starts

      const historyFrom = new Date(prevCutoff);
      historyFrom.setDate(historyFrom.getDate() - Math.max(14, lookbackWeeks * 7));

      const { data: hist, error: histErr } = await supabase
        .from('goal_progress_history')
        .select('goal_id, progress, recorded_at')
        .in('goal_id', goalIds)
        .gte('recorded_at', historyFrom.toISOString())
        .lte('recorded_at', curCutoff.toISOString())
        .order('recorded_at', { ascending: false });

      if (!histErr) {
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
    }
  } catch {
    progressDelta = null;
  }

  // --- Compute metrics ---
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
  const completedWithEvidence = completedPlans.filter((p) => {
    const link = typeof p.evidence_link === 'string' ? p.evidence_link.trim() : '';
    return link.length > 0;
  });
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
  for (const r of reports) {
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

  res.json({
    data: {
      user_id: userId,
      year: targetYear,
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
        reports_in_window: reports.length,
        weeks_with_activity: weeksWithActivity.size,
        streak_weeks: streakWeeks,
        top_blockers: topBlockers,
      },
      progress_delta: progressDelta,
    },
  });
});

// GET /manager/overview?year=2025&team_id=<uuid>&weeks=8
// Org/team overview for dashboard (adoption/coverage/progress/review/verification/execution + trends)
app.get('/manager/overview', verifyCognito, requireManager, async (req, res) => {
  const { year, team_id, weeks } = req.query;
  const targetYear = Number(year);
  if (!targetYear || Number.isNaN(targetYear)) {
    return res.status(400).json({ error: 'Query param "year" is required (number)' });
  }
  const lookbackWeeks = Math.max(1, Math.min(26, Number(weeks || 8)));
  const teamId = typeof team_id === 'string' && team_id.trim() ? team_id.trim() : null;

  const now = new Date();
  const thisWeekStart = startOfWeekMonday(now);
  const from = new Date(thisWeekStart);
  from.setDate(from.getDate() - (lookbackWeeks - 1) * 7);
  const fromStr = toDateOnly(from);
  const toStr = toDateOnly(now);

  // 0) Load teams and users (for mapping)
  const { data: teams, error: teamsErr } = await supabase.from('teams').select('id, name').order('name', { ascending: true });
  if (teamsErr) return res.status(500).json({ error: teamsErr.message });

  let usersQ = supabase.from('users').select('id, team_id, role');
  if (teamId) usersQ = usersQ.eq('team_id', teamId);
  const { data: users, error: usersErr } = await usersQ;
  if (usersErr) return res.status(500).json({ error: usersErr.message });

  const userTeam = new Map((users || []).map((u) => [u.id, u.team_id || null]));
  const membersTotalByTeam = new Map();
  for (const u of users || []) {
    const tid = u.team_id || null;
    if (!tid) continue;
    membersTotalByTeam.set(tid, (membersTotalByTeam.get(tid) || 0) + 1);
  }

  // Helper: init team buckets
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
  // Apply members totals
  for (const [tid, c] of membersTotalByTeam.entries()) {
    if (!teamAgg.has(tid)) teamAgg.set(tid, initTeamAgg());
    teamAgg.get(tid).members_total = c;
  }

  // 1) Goals (year)
  let goalsQ = supabase.from('goals').select('id, user_id, progress, review_status').eq('year', targetYear);
  if (teamId) {
    // Filter by team using users join (FK goals.user_id -> users.id)
    goalsQ = goalsQ.select(
      `
      id,
      user_id,
      progress,
      review_status,
      users!inner (
        team_id
      )
    `
    );
  }
  const { data: goalsRaw, error: goalsErr } = await goalsQ;
  if (goalsErr) return res.status(500).json({ error: goalsErr.message });

  const goals = (goalsRaw || []).map((g) => ({
    id: g.id,
    user_id: g.user_id,
    progress: Number(g.progress || 0),
    review_status: g.review_status || null,
    team_id: teamId ? g.users?.team_id ?? null : userTeam.get(g.user_id) ?? null,
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
  // members_with_goal per team
  for (const k of memberHasGoal.values()) {
    const [tid] = k.split(':');
    if (teamAgg.has(tid)) teamAgg.get(tid).members_with_goal += 1;
  }
  // progress avg per team
  for (const [tid, list] of goalsByTeam.entries()) {
    const agg = teamAgg.get(tid);
    if (!agg) continue;
    const sum = list.reduce((s, g) => s + Number(g.progress || 0), 0);
    agg.progress_avg = list.length ? Number((sum / list.length).toFixed(2)) : 0;
  }

  const goalIds = goals.map((g) => g.id).filter(Boolean);

  // 2) Action plans (join goals.year)
  let plansQ = supabase
    .from('action_plans')
    .select(
      `
      id,
      goal_id,
      status,
      end_date,
      evidence_link,
      goals!inner (
        id,
        user_id,
        year
      )
    `
    )
    .eq('goals.year', targetYear);
  const { data: plansRaw, error: plansErr } = await plansQ;
  if (plansErr) return res.status(500).json({ error: plansErr.message });

  const todayStart = new Date(now);
  todayStart.setHours(0, 0, 0, 0);

  for (const p of plansRaw || []) {
    const uid = p.goals?.user_id ?? null;
    const tid = teamId ? (userTeam.get(uid) ?? teamId) : userTeam.get(uid) ?? null;
    if (!tid) continue;
    if (teamId && tid !== teamId) continue;
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
      agg.action_plans.completed > 0
        ? Number((agg.action_plans.completed_with_evidence / agg.action_plans.completed).toFixed(4))
        : 0;
  }

  // 3) Weekly reports (window, join goals.year) for adoption + activity rate
  const reports = [];
  if (goalIds.length > 0) {
    for (const batch of chunk(goalIds, 200)) {
      const { data: rows, error: repErr } = await supabase
        .from('weekly_reports')
        .select(
          `
          goal_id,
          date,
          goals!inner (
            user_id,
            year
          )
        `
        )
        .in('goal_id', batch)
        .gte('date', fromStr)
        .lte('date', toStr);
      if (repErr) return res.status(500).json({ error: repErr.message });
      for (const r of rows || []) reports.push(r);
    }
  }

  const activeUsersThisWeekByTeam = new Map();
  const reportsByWeekByTeam = new Map(); // tid -> Map(weekKey -> Set(userId))
  for (const r of reports) {
    const uid = r.goals?.user_id ?? null;
    if (!uid) continue;
    const tid = userTeam.get(uid) ?? null;
    if (!tid) continue;
    if (teamId && tid !== teamId) continue;

    const dateOnly = typeof r.date === 'string' ? r.date.slice(0, 10) : null;
    if (!isValidDateOnly(dateOnly)) continue;

    // totals
    if (!teamAgg.has(tid)) teamAgg.set(tid, initTeamAgg());
    teamAgg.get(tid).weekly_reports.reports_in_window += 1;

    // active this week
    if (dateOnly >= toDateOnly(thisWeekStart)) {
      const set = activeUsersThisWeekByTeam.get(tid) || new Set();
      set.add(uid);
      activeUsersThisWeekByTeam.set(tid, set);
    }

    // trends
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
    agg.weekly_reports.active_rate_this_week =
      agg.members_total > 0 ? Number((set.size / agg.members_total).toFixed(4)) : 0;
  }

  // 4) Verification stats (by goal year)
  let vrQ = supabase
    .from('verification_requests')
    .select(
      `
      id,
      status,
      goal_id,
      goals!inner (
        id,
        year,
        user_id
      )
    `
    )
    .eq('goals.year', targetYear);

  const { data: vrs, error: vrErr } = await vrQ;
  if (vrErr) return res.status(500).json({ error: vrErr.message });

  for (const vr of vrs || []) {
    const uid = vr.goals?.user_id ?? null;
    const tid = uid ? userTeam.get(uid) ?? null : null;
    if (!tid) continue;
    if (teamId && tid !== teamId) continue;
    if (!teamAgg.has(tid)) teamAgg.set(tid, initTeamAgg());
    const agg = teamAgg.get(tid);
    if (vr.status === 'Reviewed') agg.verifications.reviewed += 1;
    else agg.verifications.pending += 1;
  }

  // 5) Progress delta (team/org) using goal_progress_history (lightweight: last 14 days only)
  try {
    if (goalIds.length > 0) {
      const prevCutoff = new Date(thisWeekStart);
      prevCutoff.setMilliseconds(prevCutoff.getMilliseconds() - 1);
      const historyFrom = new Date(prevCutoff);
      historyFrom.setDate(historyFrom.getDate() - 14);

      const { data: hist, error: histErr } = await supabase
        .from('goal_progress_history')
        .select('goal_id, progress, recorded_at')
        .in('goal_id', goalIds)
        .gte('recorded_at', historyFrom.toISOString())
        .lte('recorded_at', now.toISOString())
        .order('recorded_at', { ascending: false });

      if (!histErr && Array.isArray(hist)) {
        // For each goal, find latest (cur) and latest <= prevCutoff (prev)
        const cur = new Map();
        const prev = new Map();
        for (const row of hist) {
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
    }
  } catch {
    // ignore
  }

  // Build trends for selected scope (org or team)
  const weeksSeries = [];
  for (let i = lookbackWeeks - 1; i >= 0; i--) {
    const d = new Date(thisWeekStart);
    d.setDate(d.getDate() - i * 7);
    const wk = weekKey(d);

    if (teamId) {
      const m = reportsByWeekByTeam.get(teamId) || new Map();
      const set = m.get(wk) || new Set();
      const mt = teamAgg.get(teamId)?.members_total || 0;
      weeksSeries.push({
        week: wk,
        active_members: set.size,
        active_rate: mt > 0 ? Number((set.size / mt).toFixed(4)) : 0,
      });
    } else {
      // org-wide: sum active across teams (distinct per team; OK for dashboard)
      let active = 0;
      let totalMembers = 0;
      for (const [tid, agg] of teamAgg.entries()) {
        totalMembers += agg.members_total || 0;
        const m = reportsByWeekByTeam.get(tid) || new Map();
        const set = m.get(wk) || new Set();
        active += set.size;
      }
      weeksSeries.push({
        week: wk,
        active_members: active,
        active_rate: totalMembers > 0 ? Number((active / totalMembers).toFixed(4)) : 0,
      });
    }
  }

  const perTeam = (teams || [])
    .filter((t) => (teamId ? t.id === teamId : true))
    .map((t) => ({
      team_id: t.id,
      team_name: t.name,
      ...teamAgg.get(t.id),
    }));

  // org aggregate (simple sum/avg)
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
    org.action_plans.completed > 0
      ? Number((org.action_plans.completed_with_evidence / org.action_plans.completed).toFixed(4))
      : 0;
  org.weekly_reports.active_rate_this_week =
    org.members_total > 0 ? Number((org.weekly_reports.active_members_this_week / org.members_total).toFixed(4)) : 0;

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
});

// GET /manager/team-members/summary?year=2025&team_id=<uuid>&weeks=8
// Returns per-member metrics to help manager understand growth/health within a team.
app.get('/manager/team-members/summary', verifyCognito, requireManager, async (req, res) => {
  const { year, team_id, weeks } = req.query;
  const targetYear = Number(year);
  if (!targetYear || Number.isNaN(targetYear)) {
    return res.status(400).json({ error: 'Query param "year" is required (number)' });
  }
  const teamId = typeof team_id === 'string' && team_id.trim() ? team_id.trim() : null;
  if (!teamId) return res.status(400).json({ error: 'Query param "team_id" is required' });

  const lookbackWeeks = Math.max(1, Math.min(26, Number(weeks || 8)));
  const now = new Date();
  const thisWeekStart = startOfWeekMonday(now);
  const from = new Date(thisWeekStart);
  from.setDate(from.getDate() - (lookbackWeeks - 1) * 7);
  const fromStr = toDateOnly(from);
  const toStr = toDateOnly(now);

  // 0) Team users
  const { data: users, error: usersErr } = await supabase
    .from('users')
    .select('id, email, name, team_id, teams (id, name)')
    .eq('team_id', teamId)
    .order('name', { ascending: true });
  if (usersErr) return res.status(500).json({ error: usersErr.message });

  const memberIds = (users || []).map((u) => u.id).filter(Boolean);
  const teamName = users?.[0]?.teams?.name ?? null;

  // Edge case: empty team
  if (memberIds.length === 0) {
    return res.json({
      data: {
        year: targetYear,
        team_id: teamId,
        team_name: teamName,
        window: { from: fromStr, to: toStr, weeks: lookbackWeeks },
        members: [],
        top: { progress_delta: [], evidence_rate: [], overdue_plans: [], activity_streak: [] },
      },
    });
  }

  // Initialize per-member accumulator
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

  // 1) Goals for team/year
  const { data: goals, error: goalsErr } = await supabase
    .from('goals')
    .select('id, user_id, progress, review_status')
    .eq('year', targetYear)
    .in('user_id', memberIds);
  if (goalsErr) return res.status(500).json({ error: goalsErr.message });

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

  // 2) Action plans for team/year (via goals join)
  const { data: plans, error: plansErr } = await supabase
    .from('action_plans')
    .select(
      `
      id,
      goal_id,
      status,
      end_date,
      evidence_link,
      goals!inner (
        id,
        user_id,
        year
      )
    `
    )
    .eq('goals.year', targetYear)
    .in('goals.user_id', memberIds);
  if (plansErr) return res.status(500).json({ error: plansErr.message });

  const todayStart = new Date(now);
  todayStart.setHours(0, 0, 0, 0);

  for (const p of plans || []) {
    const uid = p.goals?.user_id ?? null;
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
    m.action_plans.evidence_rate =
      m.action_plans.completed > 0
        ? Number((m.action_plans.completed_with_evidence / m.action_plans.completed).toFixed(4))
        : 0;
  }

  // 3) Weekly reports in lookback window for streak/activity (join goals to avoid goal_id batching)
  const weeksByUser = new Map(); // uid -> Set(weekKey)
  for (const batch of chunk(memberIds, 200)) {
    const { data: rows, error: repErr } = await supabase
      .from('weekly_reports')
      .select(
        `
        date,
        goals!inner (
          user_id,
          year
        )
      `
      )
      .eq('goals.year', targetYear)
      .in('goals.user_id', batch)
      .gte('date', fromStr)
      .lte('date', toStr);
    if (repErr) return res.status(500).json({ error: repErr.message });

    for (const r of rows || []) {
      const uid = r.goals?.user_id ?? null;
      if (!uid) continue;
      const dateOnly = typeof r.date === 'string' ? r.date.slice(0, 10) : null;
      if (!isValidDateOnly(dateOnly)) continue;
      const m = members.get(uid);
      if (!m) continue;

      m.weekly_reports.reports_in_window += 1;
      const wk = weekKey(parseDateOnly(dateOnly));
      if (!weeksByUser.has(uid)) weeksByUser.set(uid, new Set());
      weeksByUser.get(uid).add(wk);
    }
  }

  for (const [uid, set] of weeksByUser.entries()) {
    const m = members.get(uid);
    if (!m) continue;
    m.weekly_reports.weeks_with_activity = set.size;

    // streak = continuous weeks ending at thisWeekStart
    let streak = 0;
    for (let i = 0; i < lookbackWeeks; i++) {
      const d = new Date(thisWeekStart);
      d.setDate(d.getDate() - i * 7);
      const wk = weekKey(d);
      if (set.has(wk)) streak += 1;
      else break;
    }
    m.weekly_reports.streak_weeks = streak;
  }

  // 4) Verification stats per user (by goals.year)
  const { data: vrs, error: vrErr } = await supabase
    .from('verification_requests')
    .select(
      `
      id,
      status,
      goals!inner (
        id,
        year,
        user_id
      )
    `
    )
    .eq('goals.year', targetYear)
    .in('goals.user_id', memberIds);
  if (vrErr) return res.status(500).json({ error: vrErr.message });

  for (const vr of vrs || []) {
    const uid = vr.goals?.user_id ?? null;
    const m = uid ? members.get(uid) : null;
    if (!m) continue;
    if (vr.status === 'Reviewed') m.verifications.reviewed += 1;
    else m.verifications.pending += 1;
  }

  // 5) Progress delta per user (avg across goals) from goal_progress_history
  try {
    if (goalIds.length > 0) {
      const prevCutoff = new Date(thisWeekStart);
      prevCutoff.setMilliseconds(prevCutoff.getMilliseconds() - 1);
      const historyFrom = new Date(prevCutoff);
      // For delta (this vs prev week) we only need a short window; keep it small to reduce load.
      historyFrom.setDate(historyFrom.getDate() - 14);

      const { data: hist, error: histErr } = await supabase
        .from('goal_progress_history')
        .select('goal_id, progress, recorded_at')
        .in('goal_id', goalIds)
        .gte('recorded_at', historyFrom.toISOString())
        .lte('recorded_at', now.toISOString())
        .order('recorded_at', { ascending: false });

      if (!histErr && Array.isArray(hist)) {
        const cur = new Map();
        const prev = new Map();

        for (const row of hist) {
          const gid = row.goal_id;
          if (!gid) continue;
          const recAt = row.recorded_at ? new Date(row.recorded_at) : null;
          if (!recAt || Number.isNaN(recAt.getTime())) continue;
          const p = Number(row.progress || 0);

          if (!cur.has(gid)) cur.set(gid, p);
          if (!prev.has(gid) && recAt.getTime() <= prevCutoff.getTime()) prev.set(gid, p);
          if (cur.size === goalIds.length && prev.size === goalIds.length) break;
        }

        const sumByUser = new Map();
        const cntByUser = new Map();
        for (const g of goals || []) {
          const uid = g.user_id;
          const curP = cur.has(g.id) ? cur.get(g.id) : Number(g.progress || 0);
          const prevP = prev.has(g.id) ? prev.get(g.id) : curP;
          const d = Number(curP) - Number(prevP);
          sumByUser.set(uid, (sumByUser.get(uid) || 0) + d);
          cntByUser.set(uid, (cntByUser.get(uid) || 0) + 1);
        }

        for (const [uid, sum] of sumByUser.entries()) {
          const m = members.get(uid);
          if (!m) continue;
          const cnt = cntByUser.get(uid) || 0;
          m.progress_delta = cnt ? Number((sum / cnt).toFixed(2)) : 0;
        }
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

// GET /manager/team-members/trends?year=2025&team_id=<uuid>&weeks=8
// Weekly time-series for a team: reports count per member per week (activity trend).
app.get('/manager/team-members/trends', verifyCognito, requireManager, async (req, res) => {
  const { year, team_id, weeks } = req.query;
  const targetYear = Number(year);
  if (!targetYear || Number.isNaN(targetYear)) {
    return res.status(400).json({ error: 'Query param "year" is required (number)' });
  }
  const teamId = typeof team_id === 'string' && team_id.trim() ? team_id.trim() : null;
  if (!teamId) return res.status(400).json({ error: 'Query param "team_id" is required' });

  const lookbackWeeks = Math.max(1, Math.min(26, Number(weeks || 8)));
  const now = new Date();
  const thisWeekStart = startOfWeekMonday(now);
  const from = new Date(thisWeekStart);
  from.setDate(from.getDate() - (lookbackWeeks - 1) * 7);
  const fromStr = toDateOnly(from);
  const toStr = toDateOnly(now);

  // Weeks axis (oldest -> newest)
  const weeksAxis = [];
  for (let i = lookbackWeeks - 1; i >= 0; i--) {
    const d = new Date(thisWeekStart);
    d.setDate(d.getDate() - i * 7);
    weeksAxis.push(weekKey(d));
  }
  const weekIndex = new Map(weeksAxis.map((w, i) => [w, i]));

  // Team users
  const { data: users, error: usersErr } = await supabase
    .from('users')
    .select('id, email, name, team_id, teams (id, name)')
    .eq('team_id', teamId)
    .order('name', { ascending: true });
  if (usersErr) return res.status(500).json({ error: usersErr.message });

  const memberIds = (users || []).map((u) => u.id).filter(Boolean);
  const teamName = users?.[0]?.teams?.name ?? null;

  if (memberIds.length === 0) {
    return res.json({
      data: {
        year: targetYear,
        team_id: teamId,
        team_name: teamName,
        window: { from: fromStr, to: toStr, weeks: lookbackWeeks },
        weeks: weeksAxis,
        members: [],
      },
    });
  }

  // Pre-init series arrays
  const seriesByUser = new Map();
  for (const u of users || []) {
    seriesByUser.set(u.id, {
      user_id: u.id,
      name: u.name ?? null,
      email: u.email ?? null,
      reports_by_week: Array(weeksAxis.length).fill(0),
    });
  }

  // Pull weekly_reports joined to goals (year + user scope)
  const reports = [];
  for (const batch of chunk(memberIds, 200)) {
    const { data: rows, error: repErr } = await supabase
      .from('weekly_reports')
      .select(
        `
        date,
        goals!inner (
          id,
          user_id,
          year
        )
      `
      )
      .eq('goals.year', targetYear)
      .in('goals.user_id', batch)
      .gte('date', fromStr)
      .lte('date', toStr);

    if (repErr) return res.status(500).json({ error: repErr.message });
    for (const r of rows || []) reports.push(r);
  }

  for (const r of reports) {
    const uid = r.goals?.user_id ?? null;
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

async function assertCanAccessGoal(req, goalId) {
  if (isLeaderUser(req)) return { ok: true };

  const userId = req.user.sub;
  const { data: goal, error } = await supabase
    .from('goals')
    .select('id, user_id, status, is_locked')
    .eq('id', goalId)
    .single();

  if (error || !goal) return { ok: false, status: 404, message: 'Goal not found' };
  if (goal.user_id !== userId) return { ok: false, status: 403, message: 'Forbidden' };
  return { ok: true, goal };
}

async function assertCanAccessActionPlan(req, actionPlanId) {
  if (isLeaderUser(req)) return { ok: true };

  const userId = req.user.sub;
  const { data: plan, error: planErr } = await supabase
    .from('action_plans')
    .select('id, goal_id')
    .eq('id', actionPlanId)
    .single();

  if (planErr || !plan) return { ok: false, status: 404, message: 'Action plan not found' };

  const { data: goal, error: goalErr } = await supabase
    .from('goals')
    .select('id, user_id')
    .eq('id', plan.goal_id)
    .single();

  if (goalErr || !goal) return { ok: false, status: 404, message: 'Goal not found' };
  if (goal.user_id !== userId) return { ok: false, status: 403, message: 'Forbidden' };
  return { ok: true, plan, goal };
}

async function assertCanAccessWeeklyReport(req, weeklyReportId) {
  if (isLeaderUser(req)) return { ok: true };

  const userId = req.user.sub;
  const { data: report, error: reportErr } = await supabase
    .from('weekly_reports')
    .select('id, action_plan_id')
    .eq('id', weeklyReportId)
    .single();

  if (reportErr || !report) return { ok: false, status: 404, message: 'Weekly report not found' };

  const accessPlan = await assertCanAccessActionPlan(req, report.action_plan_id);
  if (!accessPlan.ok) return accessPlan;

  // for member, assertCanAccessActionPlan already ensured ownership
  return { ok: true, report };
}

// API thêm goal
app.post('/goals', verifyCognito, async (req, res) => {
  const goal = {
    ...req.body,
    user_id: req.user.sub,
  };

  const { data, error } = await supabase
    .from('goals')
    .insert([goal])
    .select('*');;

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  res.json({ data: data[0] });
});

async function getLatestVerificationSummaryByGoalIds(goalIds) {
  const ids = Array.isArray(goalIds) ? goalIds.filter(Boolean) : [];
  if (ids.length === 0) return new Map();

  const { data, error } = await supabase
    .from('verification_requests')
    .select(
      `
      id,
      goal_id,
      status,
      created_at,
      verification_reviews (
        result,
        reviewed_at
      )
    `
    )
    .in('goal_id', ids)
    .order('created_at', { ascending: false });

  if (error) {
    console.warn('[WARN]', 'getLatestVerificationSummaryByGoalIds failed:', error.message);
    return new Map();
  }

  const map = new Map();
  for (const r of data || []) {
    const goalId = r.goal_id;
    if (!goalId || map.has(goalId)) continue;
    const review = Array.isArray(r.verification_reviews) ? r.verification_reviews[0] : null;
    map.set(goalId, {
      verification_request_id: r.id,
      verification_status: r.status || 'Pending',
      verification_requested_at: r.created_at || null,
      verification_result: review?.result ?? null,
      verification_reviewed_at: review?.reviewed_at ?? null,
    });
  }
  return map;
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

// API lấy goals theo user
app.get('/goals', verifyCognito, async (req, res) => {
  const userId = req.user.sub;

  const { data, error } = await supabase
    .from('goals')
    .select('*')
    .eq('user_id', userId);

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  const goalIds = (data || []).map((g) => g.id);
  const vmap = await getLatestVerificationSummaryByGoalIds(goalIds);
  const shaped = attachVerificationSummaryToGoals(data || [], vmap);
  res.json({ data: shaped });
});

// API Edit goal
app.put('/goals/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.sub;
  const { user_id, ...updates } = req.body;

  // Normalize progress/status rule:
  // - Keep progress within [0, 100]
  // - If progress reaches 100, auto set status = Completed
  if (typeof updates?.progress !== 'undefined') {
    const n = Number(updates.progress);
    if (!Number.isNaN(n)) {
      const clamped = Math.max(0, Math.min(100, n));
      updates.progress = clamped;
      if (clamped >= 100) {
        updates.status = 'Completed';
      }
    }
  }

  const { data: goal, error: fetchError } = await supabase
    .from('goals')
    .select('id, user_id, is_locked, review_status')
    .eq('id', id)
    .single();

  if (fetchError || !goal) {
    return res.status(404).json({ message: 'Goal not found' });
  }

  if (goal.user_id !== userId) {
    return res.status(403).json({ message: 'Forbidden' });
  }

  if (goal.is_locked) {
    // If leader already approved the goal, allow member to update status + progress only.
    // While Pending review, goal remains fully locked.
    if (goal.review_status === 'Approved') {
      const keys = Object.keys(updates || {});
      const allowedKeys = new Set(['progress', 'status']);
      const hasDisallowed = keys.some((k) => !allowedKeys.has(k));
      if (hasDisallowed) {
        return res
          .status(423)
          .json({ message: 'Goal is locked (only status/progress updates are allowed)' });
      }
      // Allowed: status/progress update continues below
    } else {
      return res.status(423).json({ message: 'Goal is locked for review' });
    }
  }

  const { data, error } = await supabase
    .from('goals')
    .update({
      ...updates,
      updated_at: new Date().toISOString(),
    })
    .eq('id', id)
    .select('*')
    .single();

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  res.json({ data });
});

// Member requests leader review (locks goal immediately)
// POST /goals/:id/request-review
app.post('/goals/:id/request-review', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.sub;

  const { data: goal, error: fetchError } = await supabase
    .from('goals')
    .select('id, user_id, review_status, is_locked')
    .eq('id', id)
    .single();

  if (fetchError || !goal) return res.status(404).json({ message: 'Goal not found' });
  if (goal.user_id !== userId) return res.status(403).json({ message: 'Forbidden' });
  if (goal.review_status === 'Approved') {
    return res.status(409).json({ message: 'Goal already approved' });
  }

  // Must have at least 1 action plan before requesting leader review
  const { data: anyPlan, error: planErr } = await supabase
    .from('action_plans')
    .select('id')
    .eq('goal_id', id)
    .limit(1);

  if (planErr) return res.status(500).json({ error: planErr.message });
  if (!anyPlan || anyPlan.length === 0) {
    return res.status(409).json({
      message: 'You must create at least one action plan before requesting leader review',
    });
  }

  const { data, error } = await supabase
    .from('goals')
    .update({
      review_status: 'Pending',
      is_locked: true,
    })
    .eq('id', id)
    .select('*')
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data });
});

// Member cancels review request (unlocks goal)
// POST /goals/:id/cancel-review
app.post('/goals/:id/cancel-review', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.sub;

  const { data: goal, error: fetchError } = await supabase
    .from('goals')
    .select('id, user_id, review_status, is_locked')
    .eq('id', id)
    .single();

  if (fetchError || !goal) return res.status(404).json({ message: 'Goal not found' });
  if (goal.user_id !== userId) return res.status(403).json({ message: 'Forbidden' });
  if (goal.review_status === 'Approved') {
    return res.status(409).json({ message: 'Goal already approved' });
  }

  const { data, error } = await supabase
    .from('goals')
    .update({
      review_status: 'Cancelled',
      is_locked: false,
    })
    .eq('id', id)
    .select('*')
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data });
});

// API get goal by year number
app.get('/action-plans', verifyCognito, async (req, res) => {
  const userId = req.user.sub;
  const { year } = req.query;

  const t0 = LOG_TIMINGS ? nowMs() : 0;
  const { data, error } = await supabase
    .from('goals')
    .select(`
      *,
      action_plans (
        *
      )
    `)
    .eq('user_id', userId)
    .eq('year', Number(year));
  if (LOG_TIMINGS) {
    const ms = nowMs() - t0;
    const goals = Array.isArray(data) ? data.length : 0;
    console.log('[DB]', `GET /action-plans supabase (${ms.toFixed(1)}ms) goals=${goals}`);
  }

  if (error) {
    console.error(error);
    return res.status(500).json({ error: error.message });
  }

  res.json({ data });
});

// Fetch weekly reports for a specific action plan (paged)
// GET /action-plans/:actionPlanId/weekly-reports?limit=20&offset=0
app.get('/action-plans/:actionPlanId/weekly-reports', verifyCognito, async (req, res) => {
  const { actionPlanId } = req.params;
  const limit = Math.max(1, Math.min(100, Number(req.query.limit || 20)));
  const offset = Math.max(0, Number(req.query.offset || 0));

  const access = await assertCanAccessActionPlan(req, actionPlanId);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  const t0 = LOG_TIMINGS ? nowMs() : 0;
  const { data, error } = await supabase
    .from('weekly_reports')
    .select('*')
    .eq('action_plan_id', actionPlanId)
    .order('date', { ascending: false })
    .range(offset, offset + limit - 1);

  if (LOG_TIMINGS) {
    const ms = nowMs() - t0;
    const count = Array.isArray(data) ? data.length : 0;
    console.log('[DB]', `GET /action-plans/:id/weekly-reports supabase (${ms.toFixed(1)}ms) rows=${count} limit=${limit} offset=${offset}`);
  }

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data, page: { limit, offset, returned: Array.isArray(data) ? data.length : 0 } });
});


// API add goal action plan
// POST /goals/:goalId/action-plans
app.post('/goals/:goalId/action-plans', verifyCognito, async (req, res) => {
  const { goalId } = req.params;

  const access = await assertCanAccessGoal(req, goalId);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  // Baseline planning: only allow adding action plans before goal starts
  if (!isLeaderUser(req)) {
    if (access.goal?.is_locked) {
      return res.status(423).json({ message: 'Goal is locked for review' });
    }
    if (access.goal?.status !== 'Not started') {
      return res.status(409).json({ message: 'Cannot add action plans after goal has started' });
    }
  }

  const actionPlan = {
    ...req.body,
    goal_id: goalId,
  };

  const { data, error } = await supabase
    .from('action_plans')
    .insert([actionPlan])
    .select('*');

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data[0] });
});


// API delete goal action plan
// DELETE /action-plans/:id
app.delete('/action-plans/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;

  const access = await assertCanAccessActionPlan(req, id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  if (!isLeaderUser(req)) {
    const { data: plan, error: planErr } = await supabase
      .from('action_plans')
      .select('id, is_locked')
      .eq('id', id)
      .single();

    if (planErr || !plan) return res.status(404).json({ message: 'Action plan not found' });
    if (plan.is_locked) return res.status(423).json({ message: 'Action plan is locked for review' });
  }

  const { error } = await supabase
    .from('action_plans')
    .delete()
    .eq('id', id);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});


// API update goal action plan
// PUT /action-plans/:id
app.put('/action-plans/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;

  const access = await assertCanAccessActionPlan(req, id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  let existingPlan = null;
  if (!isLeaderUser(req)) {
    const { data: plan, error: planErr } = await supabase
      .from('action_plans')
      .select('id, is_locked, review_status, status, start_date, end_date, request_deadline_date, deadline_change_count')
      .eq('id', id)
      .single();

    if (planErr || !plan) return res.status(404).json({ message: 'Action plan not found' });
    existingPlan = plan;

    // If pending review (locked), member can ONLY change deadline (end_date)
    if (plan.is_locked && plan.review_status === 'Pending') {
      const keys = Object.keys(req.body || {});
      const allowedKeys = new Set(['end_date']);
      const hasDisallowed = keys.some((k) => !allowedKeys.has(k));
      if (hasDisallowed) {
        return res.status(423).json({ message: 'Action plan is locked for review (deadline-only changes allowed)' });
      }
    }

    // While pending review, member cannot change status
    if (plan.review_status === 'Pending' && typeof req.body?.status !== 'undefined' && req.body.status !== plan.status) {
      return res.status(409).json({ message: 'Cannot change status while action plan is pending review' });
    }
  }

  // If member changes deadline, auto re-request leader review
  let updates = { ...(req.body || {}) };
  if (!isLeaderUser(req) && existingPlan) {
    if (typeof updates.end_date === 'string') {
      const desired = updates.end_date;
      const currentRequested = existingPlan.request_deadline_date || null;
      const currentEffective = currentRequested || existingPlan.end_date;

      // If user is requesting a different deadline, count it (max 3)
      if (desired && desired !== currentEffective) {
        const count = Number(existingPlan.deadline_change_count || 0);
        if (count >= 3) {
          return res.status(409).json({ message: 'Deadline can only be changed 3 times' });
        }

        updates = {
          ...updates,
          // store the requested deadline instead of changing end_date directly
          request_deadline_date: desired,
          deadline_change_count: count + 1,
          review_status: 'Pending',
          is_locked: true,
          leader_review_notes: null,
        };
      } else {
        // no real change; don't touch request_deadline_date/counters
        updates = { ...updates };
      }

      // never directly change end_date from member update; leader applies it on approval
      delete updates.end_date;
    }
  }

  const { data, error } = await supabase
    .from('action_plans')
    .update(updates)
    .eq('id', id)
    .select('*');

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data[0] });
});

// Member requests leader review (locks action plan immediately)
// POST /action-plans/:id/request-review
app.post('/action-plans/:id/request-review', verifyCognito, async (req, res) => {
  const { id } = req.params;

  const access = await assertCanAccessActionPlan(req, id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });
  if (isLeaderUser(req)) return res.status(403).json({ message: 'Forbidden' });

  const { data: plan, error: planErr } = await supabase
    .from('action_plans')
    .select('id, review_status')
    .eq('id', id)
    .single();

  if (planErr || !plan) return res.status(404).json({ message: 'Action plan not found' });
  if (plan.review_status === 'Approved') return res.status(409).json({ message: 'Action plan already approved' });

  const { data, error } = await supabase
    .from('action_plans')
    .update({
      review_status: 'Pending',
      is_locked: true,
    })
    .eq('id', id)
    .select('*')
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data });
});

// Member cancels review request (unlocks action plan)
// POST /action-plans/:id/cancel-review
app.post('/action-plans/:id/cancel-review', verifyCognito, async (req, res) => {
  const { id } = req.params;

  const access = await assertCanAccessActionPlan(req, id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });
  if (isLeaderUser(req)) return res.status(403).json({ message: 'Forbidden' });

  const { data: plan, error: planErr } = await supabase
    .from('action_plans')
    .select('id, review_status')
    .eq('id', id)
    .single();

  if (planErr || !plan) return res.status(404).json({ message: 'Action plan not found' });
  if (plan.review_status === 'Approved') return res.status(409).json({ message: 'Action plan already approved' });

  const { data, error } = await supabase
    .from('action_plans')
    .update({
      // action_plans table CHECK usually only allows Pending/Approved/Rejected;
      // set NULL to represent "not requested" and unlock.
      review_status: null,
      is_locked: false,
      request_deadline_date: null,
    })
    .eq('id', id)
    .select('*')
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data });
});

// Weekly Reports (member CRUD on their own; leader can CRUD all)
// POST /action-plans/:actionPlanId/weekly-reports
app.post('/action-plans/:actionPlanId/weekly-reports', verifyCognito, async (req, res) => {
  const { actionPlanId } = req.params;

  const access = await assertCanAccessActionPlan(req, actionPlanId);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  const { data: plan, error: planErr } = await supabase
    .from('action_plans')
    .select('id, goal_id, status')
    .eq('id', actionPlanId)
    .single();

  if (planErr || !plan) return res.status(404).json({ message: 'Action plan not found' });

  // Member reporting rules: only allow weekly reports while goal & plan are active
  if (!isLeaderUser(req)) {
    const { data: goal, error: goalErr } = await supabase
      .from('goals')
      .select('id, status')
      .eq('id', plan.goal_id)
      .single();

    if (goalErr || !goal) return res.status(404).json({ message: 'Goal not found' });

    const planStatus = plan.status || 'Not Started';
    const canReport =
      goal.status === 'In Progress' && (planStatus === 'In Progress' || planStatus === 'Blocked');

    if (!canReport) {
      return res.status(409).json({
        message: 'Weekly reports can only be added when goal is In Progress and action plan is In Progress/Blocked',
      });
    }
  }

  const weeklyReport = {
    ...req.body,
    action_plan_id: actionPlanId,
    goal_id: plan.goal_id,
  };

  const { data, error } = await supabase
    .from('weekly_reports')
    .insert([weeklyReport])
    .select('*');

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data[0] });
});

// PUT /weekly-reports/:id
app.put('/weekly-reports/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;

  const access = await assertCanAccessWeeklyReport(req, id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  // Only leader can update leader feedback field
  if (!isLeaderUser(req) && typeof req.body?.lead_feedback !== 'undefined') {
    return res.status(403).json({ message: 'Forbidden (leader feedback is leader-only)' });
  }

  const { data, error } = await supabase
    .from('weekly_reports')
    .update(req.body)
    .eq('id', id)
    .select('*');

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data[0] });
});

// DELETE /weekly-reports/:id
app.delete('/weekly-reports/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;

  const access = await assertCanAccessWeeklyReport(req, id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  const { error } = await supabase
    .from('weekly_reports')
    .delete()
    .eq('id', id);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});


// API Delete goal
app.delete('/goals/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.sub;

  const { data: goal, error: fetchError } = await supabase
    .from('goals')
    .select('id, user_id, is_locked')
    .eq('id', id)
    .single();

  if (fetchError || !goal) {
    return res.status(404).json({ message: 'Goal not found' });
  }

  if (goal.user_id !== userId) {
    return res.status(403).json({ message: 'Forbidden' });
  }

  if (goal.is_locked) {
    return res.status(423).json({ message: 'Goal is locked for review' });
  }

  const { error } = await supabase
    .from('goals')
    .delete()
    .eq('id', id);

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  res.json({ message: 'Goal deleted successfully' });
});


// API FOR LEADER
async function getLeaderTeamScope(req) {
  const leaderId = req.user?.sub;
  if (!leaderId) return { ok: false, status: 401, message: 'Missing leader identity' };

  const { data, error } = await supabase
    .from('users')
    .select(`
      id,
      team_id,
      teams (
        id,
        name
      )
    `)
    .eq('id', leaderId)
    .single();

  if (error || !data) return { ok: false, status: 403, message: 'Leader team scope not found' };
  if (!data.team_id) return { ok: false, status: 403, message: 'Leader is not assigned to a team' };

  return {
    ok: true,
    teamId: data.team_id,
    teamName: data.teams?.name ?? null,
  };
}

app.get('/leader/goals', verifyCognito, requireLeader, async (req, res) => {
  const t0 = LOG_TIMINGS ? nowMs() : 0;
  const { year, user_id, team_id, limit, offset } = req.query;
  const pageLimit = Math.max(1, Math.min(500, Number(limit || 200)));
  const pageOffset = Math.max(0, Number(offset || 0));

  const scope = await getLeaderTeamScope(req);
  if (!scope.ok) return res.status(scope.status).json({ message: scope.message });

  // If client tries to query another team, block it.
  if (typeof team_id === 'string' && team_id.trim() && team_id.trim() !== scope.teamId) {
    return res.status(403).json({ message: 'Forbidden (team scope)' });
  }

  let q = supabase
    .from('goals')
    .select(
      `
      *,
      action_plans (
        *
      ),
      users!inner (
        id,
        email,
        name,
        team_id,
        teams (
          id,
          name
        )
      )
    `
    )
    .range(pageOffset, pageOffset + pageLimit - 1);

  if (typeof year !== 'undefined' && year !== null && `${year}`.trim() !== '') {
    q = q.eq('year', Number(year));
  }
  if (typeof user_id === 'string' && user_id.trim()) {
    // Filter by goal owner (Cognito sub UUID)
    q = q.eq('user_id', user_id.trim());
  }
  // Always enforce leader's team (multi-leader, per-team scope)
  q = q.eq('users.team_id', scope.teamId);

  const { data, error } = await q;
  if (LOG_TIMINGS) {
    const ms = nowMs() - t0;
    const goals = Array.isArray(data) ? data.length : 0;
    console.log(
      '[DB]',
      `GET /leader/goals supabase (${ms.toFixed(1)}ms) goals=${goals} limit=${pageLimit} offset=${pageOffset}${typeof year !== 'undefined' ? ` year=${year}` : ''}${typeof user_id === 'string' && user_id.trim() ? ` user_id=${user_id}` : ''}${typeof team_id === 'string' && team_id.trim() ? ` team_id=${team_id}` : ''}`
    );
  }

  if (error) return res.status(500).json({ error: error.message });
  // Backward-compatible shaping: keep existing goal fields but derive member/team from joined users/teams.
  const shaped =
    (data || []).map((g) => {
      const u = g.users || null;
      const teamObj = u?.teams || null;
      return {
        ...g,
        user_name: u?.name ?? g.user_name ?? null,
        user_email: u?.email ?? g.user_email ?? null,
        team_id: u?.team_id ?? g.team_id ?? null,
        team: teamObj?.name ?? g.team ?? null,
        users: undefined,
      };
    }) || [];

  const goalIds = shaped.map((g) => g.id);
  const vmap = await getLatestVerificationSummaryByGoalIds(goalIds);
  const withVerify = attachVerificationSummaryToGoals(shaped, vmap);
  res.json({ data: withVerify });
});

// Leader: summary stats for goals (NOT paged)
// GET /leader/goals/summary?year=2025&team_id=<uuid>&user_id=<uuid>
app.get('/leader/goals/summary', verifyCognito, requireLeader, async (req, res) => {
  const t0 = LOG_TIMINGS ? nowMs() : 0;
  const { year, user_id, team_id } = req.query;

  const scope = await getLeaderTeamScope(req);
  if (!scope.ok) return res.status(scope.status).json({ message: scope.message });

  if (typeof team_id === 'string' && team_id.trim() && team_id.trim() !== scope.teamId) {
    return res.status(403).json({ message: 'Forbidden (team scope)' });
  }

  const targetYear = typeof year !== 'undefined' && year !== null && `${year}`.trim() !== ''
    ? Number(year)
    : null;
  if (!targetYear || Number.isNaN(targetYear)) {
    return res.status(400).json({ error: 'Query param "year" is required (number)' });
  }

  const pageLimit = 500;
  let offset = 0;
  let total = 0;
  let approved = 0;
  let pending = 0;
  let progressSum = 0;

  while (true) {
    let q = supabase
      .from('goals')
      .select(
        `
        id,
        progress,
        review_status,
        users!inner (
          id,
          team_id,
          teams (
            id,
            name
          )
        )
      `
      )
      .eq('year', targetYear)
      .range(offset, offset + pageLimit - 1);

    if (typeof user_id === 'string' && user_id.trim()) {
      q = q.eq('user_id', user_id.trim());
    }
    // Always enforce leader's team (multi-leader, per-team scope)
    q = q.eq('users.team_id', scope.teamId);

    const { data, error } = await q;
    if (error) return res.status(500).json({ error: error.message });

    const rows = Array.isArray(data) ? data : [];
    for (const g of rows) {
      total += 1;
      const rs = g.review_status || null;
      if (rs === 'Approved') approved += 1;
      if (!rs || rs === 'Pending') pending += 1;
      progressSum += Number(g.progress || 0);
    }

    if (rows.length < pageLimit) break;
    offset += pageLimit;
    // Safety: avoid infinite loops if upstream misbehaves
    if (offset > 100000) break;
  }

  const avgProgress = total > 0 ? progressSum / total : 0;

  if (LOG_TIMINGS) {
    const ms = nowMs() - t0;
    console.log(
      '[DB]',
      `GET /leader/goals/summary supabase (${ms.toFixed(1)}ms) total=${total} year=${targetYear}${typeof user_id === 'string' && user_id.trim() ? ` user_id=${user_id.trim()}` : ''}${typeof team_id === 'string' && team_id.trim() ? ` team_id=${team_id.trim()}` : ''}`
    );
  }

  res.json({ data: { total, approved, pending, avgProgress } });
});

// Leader: list users for dropdown filters (requires `users` table: id(uuid)=cognito sub)
// GET /leader/users?q=...&team=...&limit=200&offset=0
app.get('/leader/users', verifyCognito, requireLeader, async (req, res) => {
  const { q, team, team_id, limit, offset } = req.query;
  const pageLimit = Math.max(1, Math.min(500, Number(limit || 200)));
  const pageOffset = Math.max(0, Number(offset || 0));

  const scope = await getLeaderTeamScope(req);
  if (!scope.ok) return res.status(scope.status).json({ message: scope.message });

  const t0 = LOG_TIMINGS ? nowMs() : 0;

  let query = supabase
    .from('users')
    .select(`
      id,
      email,
      name,
      team_id,
      role,
      teams (
        id,
        name
      )
    `)
    .range(pageOffset, pageOffset + pageLimit - 1)
    .order('name', { ascending: true, nullsFirst: false });

  const teamId = typeof team_id === 'string' && team_id.trim()
    ? team_id.trim()
    : typeof team === 'string' && team.trim()
      ? team.trim()
      : null;
  if (teamId && teamId !== scope.teamId) {
    return res.status(403).json({ message: 'Forbidden (team scope)' });
  }

  // Always enforce leader's team (multi-leader, per-team scope)
  query = query.eq('team_id', scope.teamId);
  if (typeof q === 'string' && q.trim()) {
    const needle = q.trim();
    // Supabase "or" filter for simple search
    query = query.or(`name.ilike.%${needle}%,email.ilike.%${needle}%`);
  }

  const { data, error } = await query;

  if (LOG_TIMINGS) {
    const ms = nowMs() - t0;
    const rows = Array.isArray(data) ? data.length : 0;
    console.log('[DB]', `GET /leader/users supabase (${ms.toFixed(1)}ms) rows=${rows} limit=${pageLimit} offset=${pageOffset}`);
  }

  if (error) return res.status(500).json({ error: error.message });
  const shaped =
    (data || []).map((u) => ({
      id: u.id,
      email: u.email ?? null,
      name: u.name ?? null,
      team_id: u.team_id ?? null,
      team_name: u.teams?.name ?? null,
      role: u.role ?? null,
    })) || [];
  res.json({ data: shaped, page: { limit: pageLimit, offset: pageOffset, returned: Array.isArray(data) ? data.length : 0 } });
});

// Leader: list teams for dropdown filters
// GET /leader/teams
app.get('/leader/teams', verifyCognito, requireLeader, async (req, res) => {
  const scope = await getLeaderTeamScope(req);
  if (!scope.ok) return res.status(scope.status).json({ message: scope.message });

  const { data, error } = await supabase
    .from('teams')
    .select('id, name')
    .eq('id', scope.teamId)
    .order('name', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data || [] });
});

// --- Verifications (member submit, leader review) ---

// GET /verification-templates (authenticated)
app.get('/verification-templates', verifyCognito, async (req, res) => {
  const { data, error } = await supabase
    .from('verification_templates')
    .select('id, name, category, scoring_type, criteria, required_evidence, minimum_bar')
    .order('name', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data || [] });
});

// POST /verification-templates (leader only)
app.post('/verification-templates', verifyCognito, requireLeader, async (req, res) => {
  const leaderId = req.user.sub;
  const { name, category, scoring_type, criteria, required_evidence, minimum_bar } = req.body || {};

  if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name is required' });

  const payload = {
    name: name.trim(),
    category: typeof category === 'string' ? category.trim() : null,
    scoring_type: typeof scoring_type === 'string' ? scoring_type : 'rubric',
    criteria: Array.isArray(criteria) ? criteria : [],
    required_evidence: Array.isArray(required_evidence) ? required_evidence : [],
    minimum_bar: minimum_bar && typeof minimum_bar === 'object' ? minimum_bar : null,
    created_by: leaderId,
  };

  const { data, error } = await supabase.from('verification_templates').insert([payload]).select('*').single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data });
});

// POST /verification-requests (member creates request)
app.post('/verification-requests', verifyCognito, async (req, res) => {
  const requesterId = req.user.sub;
  const { goal_id, action_plan_id, template_id, scope, evidence_links, rubric_snapshot, member_notes } = req.body || {};

  if (!goal_id || typeof goal_id !== 'string') return res.status(400).json({ error: 'goal_id is required' });
  if (!scope || typeof scope !== 'string') return res.status(400).json({ error: 'scope is required' });

  const access = await assertCanAccessGoal(req, goal_id);
  if (!access.ok) return res.status(access.status).json({ message: access.message });

  const payload = {
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

  const { data, error } = await supabase.from('verification_requests').insert([payload]).select('*').single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data });
});

// GET /verification-requests
// - member: own requests
// - leader: team-scoped queue, optional filters: status, year, user_id
app.get('/verification-requests', verifyCognito, async (req, res) => {
  const isLeader = isLeaderUser(req);
  const me = req.user.sub;
  const { year, status, user_id, team_id, limit, offset } = req.query;
  const pageLimit = Math.max(1, Math.min(200, Number(limit || 50)));
  const pageOffset = Math.max(0, Number(offset || 0));

  let q = supabase
    .from('verification_requests')
    .select(
      `
      id,
      requester_id,
      goal_id,
      action_plan_id,
      template_id,
      scope,
      evidence_links,
      status,
      created_at,
      updated_at,
      goals!inner (
        id,
        name,
        year,
        user_id
      ),
      users!inner (
        id,
        name,
        email,
        team_id,
        teams ( id, name )
      )
    `
    )
    .range(pageOffset, pageOffset + pageLimit - 1)
    .order('created_at', { ascending: false });

  if (!isLeader) {
    q = q.eq('requester_id', me);
  } else {
    const scope = await getLeaderTeamScope(req);
    if (!scope.ok) return res.status(scope.status).json({ message: scope.message });
    if (typeof team_id === 'string' && team_id.trim() && team_id.trim() !== scope.teamId) {
      return res.status(403).json({ message: 'Forbidden (team scope)' });
    }
    q = q.eq('users.team_id', scope.teamId);
    if (typeof user_id === 'string' && user_id.trim()) q = q.eq('requester_id', user_id.trim());
  }

  if (typeof year !== 'undefined' && `${year}`.trim() !== '') q = q.eq('goals.year', Number(year));
  if (typeof status === 'string' && status.trim()) q = q.eq('status', status.trim());

  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });

  const shaped = (data || []).map((r) => {
    const u = r.users || null;
    const t = u?.teams || null;
    return {
      ...r,
      member_name: u?.name ?? null,
      member_email: u?.email ?? null,
      team_id: u?.team_id ?? null,
      team_name: t?.name ?? null,
      goal: r.goals ?? null,
      users: undefined,
      goals: undefined,
    };
  });

  res.json({ data: shaped, page: { limit: pageLimit, offset: pageOffset, returned: shaped.length } });
});

// GET /verification-requests/:id
app.get('/verification-requests/:id', verifyCognito, async (req, res) => {
  const { id } = req.params;
  const isLeader = isLeaderUser(req);
  const me = req.user.sub;

  const { data, error } = await supabase
    .from('verification_requests')
    .select(
      `
      *,
      verification_reviews (*),
      goals!inner ( id, name, year, user_id ),
      users!inner ( id, name, email, team_id, teams (id, name) )
    `
    )
    .eq('id', id)
    .single();
  if (error || !data) return res.status(404).json({ error: 'Not found' });

  if (!isLeader && data.requester_id !== me) return res.status(403).json({ message: 'Forbidden' });
  if (isLeader) {
    const scope = await getLeaderTeamScope(req);
    if (!scope.ok) return res.status(scope.status).json({ message: scope.message });
    if (data.users?.team_id !== scope.teamId) return res.status(403).json({ message: 'Forbidden (team scope)' });
  }

  const shaped = {
    ...data,
    member_name: data.users?.name ?? null,
    member_email: data.users?.email ?? null,
    team_id: data.users?.team_id ?? null,
    team_name: data.users?.teams?.name ?? null,
    goal: data.goals ?? null,
    users: undefined,
    goals: undefined,
  };

  res.json({ data: shaped });
});

// POST /verification-requests/:id/review (leader)
app.post('/verification-requests/:id/review', verifyCognito, requireLeader, async (req, res) => {
  const { id } = req.params;
  const leaderId = req.user.sub;
  const { result, scores, leader_feedback } = req.body || {};

  if (!result || !['Pass', 'NeedsWork', 'Fail'].includes(result)) {
    return res.status(400).json({ error: 'result must be Pass/NeedsWork/Fail' });
  }

  const { data: vr, error: vrErr } = await supabase
    .from('verification_requests')
    .select('id, requester_id, status, users!inner (team_id)')
    .eq('id', id)
    .single();
  if (vrErr || !vr) return res.status(404).json({ error: 'Not found' });

  const scope = await getLeaderTeamScope(req);
  if (!scope.ok) return res.status(scope.status).json({ message: scope.message });
  if (vr.users?.team_id !== scope.teamId) return res.status(403).json({ message: 'Forbidden (team scope)' });

  const reviewPayload = {
    request_id: vr.id,
    leader_id: leaderId,
    result,
    scores: scores && typeof scores === 'object' ? scores : {},
    leader_feedback: typeof leader_feedback === 'string' ? leader_feedback : null,
  };

  const { data: review, error: reviewErr } = await supabase
    .from('verification_reviews')
    .upsert([reviewPayload], { onConflict: 'request_id' })
    .select('*')
    .single();
  if (reviewErr) return res.status(500).json({ error: reviewErr.message });

  const { error: updErr } = await supabase
    .from('verification_requests')
    .update({ status: 'Reviewed', updated_at: new Date().toISOString() })
    .eq('id', vr.id);
  if (updErr) return res.status(500).json({ error: updErr.message });

  res.json({ data: { review } });
});

// Leader: aggregate "growth" metrics for a member (for dashboard insights)
// GET /leader/member-insights?year=2025&user_id=<uuid>&weeks=8
app.get('/leader/member-insights', verifyCognito, requireLeader, async (req, res) => {
  const { year, user_id, weeks } = req.query;
  const targetYear = Number(year);
  if (!targetYear || Number.isNaN(targetYear)) {
    return res.status(400).json({ error: 'Query param "year" is required (number)' });
  }
  if (typeof user_id !== 'string' || !user_id.trim()) {
    return res.status(400).json({ error: 'Query param "user_id" is required' });
  }

  const userId = user_id.trim();
  const lookbackWeeks = Math.max(1, Math.min(26, Number(weeks || 8)));

  const toDateOnly = (d) => d.toISOString().slice(0, 10);
  const parseDateOnly = (s) => {
    const [y, m, dd] = `${s}`.slice(0, 10).split('-').map(Number);
    const d = new Date(y, (m || 1) - 1, dd || 1);
    d.setHours(0, 0, 0, 0);
    return d;
  };
  const startOfWeekMonday = (d) => {
    const date = new Date(d);
    const day = (date.getDay() + 6) % 7; // Monday=0
    date.setHours(0, 0, 0, 0);
    date.setDate(date.getDate() - day);
    return date;
  };
  const weekKey = (d) => toDateOnly(startOfWeekMonday(d));

  const now = new Date();
  const thisWeekStart = startOfWeekMonday(now);
  const from = new Date(thisWeekStart);
  from.setDate(from.getDate() - (lookbackWeeks - 1) * 7);
  const fromStr = toDateOnly(from);
  const toStr = toDateOnly(now);

  const t0 = LOG_TIMINGS ? nowMs() : 0;

  // 1) Goals for member/year
  const { data: goals, error: goalsErr } = await supabase
    .from('goals')
    .select('id, user_id, year, progress, status, review_status, start_date, time_bound, updated_at')
    .eq('user_id', userId)
    .eq('year', targetYear);
  if (goalsErr) return res.status(500).json({ error: goalsErr.message });

  const goalIds = (goals || []).map((g) => g.id).filter(Boolean);
  const goalProgressById = new Map((goals || []).map((g) => [g.id, Number(g.progress || 0)]));

  // 2) Action plans for member/year (join via goals)
  const { data: plans, error: plansErr } = await supabase
    .from('action_plans')
    .select(
      `
      id,
      goal_id,
      status,
      start_date,
      end_date,
      evidence_link,
      goals!inner (
        user_id,
        year
      )
    `
    )
    .eq('goals.user_id', userId)
    .eq('goals.year', targetYear);
  if (plansErr) return res.status(500).json({ error: plansErr.message });

  // 3) Weekly reports in lookback window (via goal ids) — used for streak + blockers summary
  const isValidDateOnly = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
  const chunk = (arr, size) => {
    const out = [];
    for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
    return out;
  };

  const reports = [];
  if (goalIds.length > 0) {
    for (const batch of chunk(goalIds, 200)) {
      const { data: rows, error: repErr } = await supabase
        .from('weekly_reports')
        .select('goal_id, action_plan_id, date, blockers_challenges')
        .in('goal_id', batch)
        .gte('date', fromStr)
        .lte('date', toStr);
      if (repErr) return res.status(500).json({ error: repErr.message });
      for (const r of rows || []) reports.push(r);
    }
  }

  // 4) Progress delta (avg progress this week vs previous week) using goal_progress_history
  // Requires the user to have run the migration script.
  let progressDelta = null;
  try {
    if (goalIds.length > 0) {
      const curCutoff = now; // now
      const prevCutoff = new Date(thisWeekStart);
      prevCutoff.setMilliseconds(prevCutoff.getMilliseconds() - 1); // just before this week starts

      // Pull enough history rows to find latest record <= each cutoff
      const historyFrom = new Date(prevCutoff);
      historyFrom.setDate(historyFrom.getDate() - Math.max(14, lookbackWeeks * 7));

      const { data: hist, error: histErr } = await supabase
        .from('goal_progress_history')
        .select('goal_id, progress, recorded_at')
        .in('goal_id', goalIds)
        .gte('recorded_at', historyFrom.toISOString())
        .lte('recorded_at', curCutoff.toISOString())
        .order('recorded_at', { ascending: false });

      if (!histErr) {
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
          const prevP = prev.has(gid) ? prev.get(gid) : curP; // fallback: no prior record => assume unchanged
          curVals.push(curP);
          prevVals.push(prevP);
        }

        const avg = (xs) => (xs.length ? xs.reduce((s, x) => s + x, 0) / xs.length : 0);
        progressDelta = Number((avg(curVals) - avg(prevVals)).toFixed(2));
      }
    }
  } catch {
    // If table doesn't exist or query fails, keep null.
    progressDelta = null;
  }

  // --- Compute metrics ---
  const totalGoals = (goals || []).length;
  const approvedGoals = (goals || []).filter((g) => g.review_status === 'Approved').length;
  const pendingGoals = (goals || []).filter((g) => !g.review_status || g.review_status === 'Pending').length;

  // Health buckets (mirror frontend heuristic)
  const msDay = 24 * 3600 * 1000;
  const goalHealth = { onTrack: 0, atRisk: 0, highRisk: 0, stagnant: 0 };
  for (const g of goals || []) {
    const start = g.start_date ? new Date(g.start_date) : null;
    const end = g.time_bound ? new Date(g.time_bound) : null;
    const progress = Number(g.progress || 0);

    // Stagnant: approved + 0% for >10 days since start (simple, stable)
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

  // Action plan metrics
  const allPlans = plans || [];
  const totalPlans = allPlans.length;
  const completedPlans = allPlans.filter((p) => p.status === 'Completed');
  const completedWithEvidence = completedPlans.filter((p) => {
    const link = typeof p.evidence_link === 'string' ? p.evidence_link.trim() : '';
    return link.length > 0;
  });
  const evidenceRate =
    completedPlans.length > 0 ? completedWithEvidence.length / completedPlans.length : 0;

  const todayStart = new Date(now);
  todayStart.setHours(0, 0, 0, 0);
  const overduePlans = allPlans.filter((p) => {
    if (!p.end_date) return false;
    const end = parseDateOnly(p.end_date);
    if (Number.isNaN(end.getTime())) return false;
    if (p.status === 'Completed') return false;
    return end.getTime() < todayStart.getTime();
  });

  // Weekly activity streak (weeks with at least 1 report)
  const weeksWithActivity = new Set();
  const blockersCount = new Map();
  for (const r of reports) {
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

  if (LOG_TIMINGS) {
    const ms = nowMs() - t0;
    console.log('[DB]', `GET /leader/member-insights (${ms.toFixed(1)}ms) goals=${totalGoals} plans=${totalPlans} reports=${reports.length}`);
  }

  res.json({
    data: {
      user_id: userId,
      year: targetYear,
      window: { from: fromStr, to: toStr, weeks: lookbackWeeks },
      goals: {
        total: totalGoals,
        approved: approvedGoals,
        pending: pendingGoals,
        health: goalHealth,
      },
      action_plans: {
        total: totalPlans,
        overdue: overduePlans.length,
        completed: completedPlans.length,
        completed_with_evidence: completedWithEvidence.length,
        evidence_rate: evidenceRate,
      },
      weekly_reports: {
        reports_in_window: reports.length,
        weeks_with_activity: weeksWithActivity.size,
        streak_weeks: streakWeeks,
        top_blockers: topBlockers,
      },
      // Average progress delta (percentage points) for the member this week vs previous week
      progress_delta: progressDelta,
    },
  });
});

// Leader insights: weekly report stats per action plan for a date range
// GET /leader/action-plans/weekly-report-stats?year=2025&user_id=<uuid>&from=YYYY-MM-DD&to=YYYY-MM-DD
// Returns: { data: { [actionPlanId]: { lastReportDate: string|null, hasReportInRange: boolean } }, meta: {...} }
app.get('/leader/action-plans/weekly-report-stats', verifyCognito, requireLeader, async (req, res) => {
  const { year, user_id, from, to } = req.query;
  const fromStr = typeof from === 'string' ? from.slice(0, 10) : null;
  const toStr = typeof to === 'string' ? to.slice(0, 10) : null;

  const isValidDateOnly = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
  if (!isValidDateOnly(fromStr) || !isValidDateOnly(toStr)) {
    return res.status(400).json({ error: 'Query params "from" and "to" (YYYY-MM-DD) are required' });
  }

  const targetYear =
    typeof year !== 'undefined' && year !== null && `${year}`.trim() !== '' ? Number(year) : null;
  if (targetYear == null || Number.isNaN(targetYear)) {
    return res.status(400).json({ error: 'Query param "year" is required' });
  }

  // 1) Find relevant action plans (goal in progress + plan in progress/blocked) for the given year/user.
  const t0 = LOG_TIMINGS ? nowMs() : 0;
  let plansQ = supabase
    .from('action_plans')
    .select(
      `
      id,
      start_date,
      status,
      goals!inner (
        id,
        user_id,
        year,
        status
      )
    `
    )
    .in('status', ['In Progress', 'Blocked'])
    .eq('goals.status', 'In Progress')
    .eq('goals.year', targetYear);

  if (typeof user_id === 'string' && user_id.trim()) {
    plansQ = plansQ.eq('goals.user_id', user_id.trim());
  }

  const { data: plans, error: plansErr } = await plansQ;
  if (LOG_TIMINGS) {
    const ms = nowMs() - t0;
    const count = Array.isArray(plans) ? plans.length : 0;
    console.log('[DB]', `GET /leader/action-plans/weekly-report-stats plans (${ms.toFixed(1)}ms) rows=${count}`);
  }
  if (plansErr) return res.status(500).json({ error: plansErr.message });

  const planIds = (plans || []).map((p) => p.id).filter(Boolean);
  const stats = {};
  for (const id of planIds) {
    stats[id] = { lastReportDate: null, hasReportInRange: false };
  }

  // 2) Fetch weekly reports for those plans (chunked) and compute stats in JS.
  const chunk = (arr, size) => {
    const out = [];
    for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
    return out;
  };

  const t1 = LOG_TIMINGS ? nowMs() : 0;
  let reportRows = 0;
  for (const batch of chunk(planIds, 200)) {
    if (batch.length === 0) continue;
    const { data: reports, error: reportsErr } = await supabase
      .from('weekly_reports')
      .select('action_plan_id, date')
      .in('action_plan_id', batch);

    if (reportsErr) return res.status(500).json({ error: reportsErr.message });

    for (const r of reports || []) {
      const planId = r.action_plan_id;
      if (!planId) continue;
      const dateOnly = typeof r.date === 'string' ? r.date.slice(0, 10) : null;
      if (!isValidDateOnly(dateOnly)) continue;

      if (!stats[planId]) stats[planId] = { lastReportDate: null, hasReportInRange: false };

      // lastReportDate (max)
      if (!stats[planId].lastReportDate || dateOnly > stats[planId].lastReportDate) {
        stats[planId].lastReportDate = dateOnly;
      }

      // in-range flag
      if (dateOnly >= fromStr && dateOnly <= toStr) {
        stats[planId].hasReportInRange = true;
      }
    }
    reportRows += Array.isArray(reports) ? reports.length : 0;
  }
  if (LOG_TIMINGS) {
    const ms = nowMs() - t1;
    console.log('[DB]', `GET /leader/action-plans/weekly-report-stats reports (${ms.toFixed(1)}ms) rows=${reportRows}`);
  }

  res.json({
    data: stats,
    meta: {
      year: targetYear,
      user_id: typeof user_id === 'string' && user_id.trim() ? user_id.trim() : null,
      from: fromStr,
      to: toStr,
      plans: planIds.length,
      reports: reportRows,
    },
  });
});

// API leader update goal
app.put('/leader/goals/:id', verifyCognito, requireLeader, async (req, res) => {
  const { id } = req.params;

  const { data, error } = await supabase
    .from('goals')
    .update(req.body)
    .eq('id', id)
    .select('*')
    .single();

  if (error) return res.status(500).json({ error: error.message });

  res.json({ data });
});

async function getReviewerIdentity(req) {
  const reviewerId = req.user?.sub ?? null;
  if (!reviewerId) return { id: null, email: null, name: null };
  try {
    const { data } = await supabase
      .from('users')
      .select('id, email, name')
      .eq('id', reviewerId)
      .single();
    return {
      id: reviewerId,
      email: data?.email ?? null,
      name: data?.name ?? null,
    };
  } catch {
    return { id: reviewerId, email: null, name: null };
  }
}

function isMissingColumnError(err) {
  const msg = (err?.message || '').toLowerCase();
  return msg.includes('does not exist') && msg.includes('column');
}

app.put('/leader/goals/:id/review', verifyCognito, requireLeader, async (req, res) => {
  const { id } = req.params;
  const { status, comment } = req.body;
  const lock =
    status === 'Approved'
      ? true
      : status === 'Rejected' || status === 'Cancelled'
        ? false
        : true; // Pending (or unknown) => locked

  const { data: existing, error: fetchErr } = await supabase
    .from('goals')
    .select('id, status')
    .eq('id', id)
    .single();

  if (fetchErr || !existing) return res.status(404).json({ message: 'Goal not found' });

  const nextStatus =
    status === 'Approved' && (existing.status === 'Not started' || existing.status === 'Draft')
      ? 'In Progress'
      : existing.status;

  const nowIso = new Date().toISOString();
  const reviewer = await getReviewerIdentity(req);

  const baseUpdate = {
    review_status: status,
    leader_review_notes: comment,
    is_locked: lock,
    status: nextStatus,
  };

  const auditUpdate = {
    ...baseUpdate,
    reviewed_by: reviewer.id,
    reviewed_by_email: reviewer.email,
    reviewed_by_name: reviewer.name,
    reviewed_at: nowIso,
    approved_at: status === 'Approved' ? nowIso : null,
    rejected_at: status === 'Rejected' ? nowIso : null,
  };

  // Backward compatible: if audit columns don't exist in DB, retry with base fields only.
  let error = null;
  {
    const attempt = await supabase.from('goals').update(auditUpdate).eq('id', id);
    error = attempt.error;
    if (error && isMissingColumnError(error)) {
      const attempt2 = await supabase.from('goals').update(baseUpdate).eq('id', id);
      error = attempt2.error;
    }
  }

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// Leader review Action Plan
// PUT /leader/action-plans/:id/review
app.put('/leader/action-plans/:id/review', verifyCognito, requireLeader, async (req, res) => {
  const { id } = req.params;
  const { status, comment } = req.body;
  // For action plans: lock only while pending. After leader approves/rejects, member can continue editing status.
  const lock = status === 'Pending';

  const { data: plan, error: fetchErr } = await supabase
    .from('action_plans')
    .select('id, request_deadline_date')
    .eq('id', id)
    .single();

  if (fetchErr || !plan) return res.status(404).json({ message: 'Action plan not found' });

  const updatePayload = {
    review_status: status,
    leader_review_notes: comment,
    is_locked: lock,
  };

  // If leader approves, apply requested deadline (if any). If rejected, clear it.
  if (status === 'Approved' && plan.request_deadline_date) {
    updatePayload.end_date = plan.request_deadline_date;
    updatePayload.request_deadline_date = null;
  }
  if (status === 'Rejected') {
    updatePayload.request_deadline_date = null;
  }

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

  // Backward compatible: if audit columns don't exist in DB, retry with base fields only.
  let error = null;
  {
    const attempt = await supabase.from('action_plans').update(auditUpdate).eq('id', id);
    error = attempt.error;
    if (error && isMissingColumnError(error)) {
      const attempt2 = await supabase.from('action_plans').update(baseUpdate).eq('id', id);
      error = attempt2.error;
    }
  }

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.listen(3000, () => {
  console.log('Goal service running on http://localhost:3000');
});
