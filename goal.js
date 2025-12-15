import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import supabase from './config/supabaseClient.js';
import { verifyCognito, requireLeader } from './middleware/verifyCognito.js';

const app = express();
app.use(cors());
app.use(bodyParser.json());

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
    return res.status(423).json({ message: 'Goal is locked for review' });
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

  const { data, error } = await supabase
    .from('goals')
    .select(`
      *,
      action_plans (
        *,
        weekly_reports (*)
      )
    `)
    .eq('user_id', userId)
    .eq('year', Number(year));

  if (error) {
    console.error(error);
    return res.status(500).json({ error: error.message });
  }

  res.json({ data });
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
  const { data, error } = await supabase
    .from('goals')
    .select(`
      *,
      action_plans (
        *,
        weekly_reports (*)
      )
    `);

  console.log(data);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data });
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
