import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import supabase from './config/supabaseClient.js';
import { verifyCognito, requireLeader } from './middleware/verifyCognito.js';

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

  res.json({ data });
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
app.get('/leader/goals', verifyCognito, requireLeader, async (req, res) => {
  const t0 = LOG_TIMINGS ? nowMs() : 0;
  const { year, user_id, team_id, limit, offset } = req.query;
  const pageLimit = Math.max(1, Math.min(500, Number(limit || 200)));
  const pageOffset = Math.max(0, Number(offset || 0));

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
  if (typeof team_id === 'string' && team_id.trim()) {
    // Filter by user's team (users.team_id -> teams.id)
    q = q.eq('users.team_id', team_id.trim());
  }

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

  res.json({ data: shaped });
});

// Leader: list users for dropdown filters (requires `users` table: id(uuid)=cognito sub)
// GET /leader/users?q=...&team=...&limit=200&offset=0
app.get('/leader/users', verifyCognito, requireLeader, async (req, res) => {
  const { q, team, team_id, limit, offset } = req.query;
  const pageLimit = Math.max(1, Math.min(500, Number(limit || 200)));
  const pageOffset = Math.max(0, Number(offset || 0));

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
  if (teamId) query = query.eq('team_id', teamId);
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
  const { data, error } = await supabase
    .from('teams')
    .select('id, name')
    .order('name', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data || [] });
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

  const { error } = await supabase
    .from('goals')
    .update({
      review_status: status,
      leader_review_notes: comment,
      is_locked: lock,
      status: nextStatus,
    })
    .eq('id', id);

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

  const { error } = await supabase
    .from('action_plans')
    .update(updatePayload)
    .eq('id', id);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.listen(3000, () => {
  console.log('Goal service running on http://localhost:3000');
});
