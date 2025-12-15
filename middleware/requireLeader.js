export function requireLeader(req, res, next) {
  const groups = req.user?.['cognito:groups'];
  const groupList = Array.isArray(groups)
    ? groups
    : typeof groups === 'string'
      ? [groups]
      : [];

  if (!groupList.includes('leader')) {
    return res.status(403).json({ message: 'Forbidden (Leader only)' });
  }

  next();
}