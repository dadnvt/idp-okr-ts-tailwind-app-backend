import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

const client = jwksClient({
  jwksUri:
    'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ilPTEVT0U/.well-known/jwks.json',
  // Reduce latency spikes: cache keys locally and rate-limit JWKS calls.
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 1000, // 10 minutes
  rateLimit: true,
  jwksRequestsPerMinute: 10,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) return callback(err);
    if (!key) return callback(new Error('JWKS signing key not found'));
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

export function verifyCognito(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: 'Missing Authorization header' });
  }

  const token = authHeader.replace('Bearer ', '');

  jwt.verify(
    token,
    getKey,
    {
      issuer:
        'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ilPTEVT0U',
      algorithms: ['RS256'],
    },
    (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid token' });
      }

      req.user = decoded; 
      next();
    }
  );
}

function getCognitoGroupList(req) {
  const groups = req.user?.['cognito:groups'];
  return Array.isArray(groups) ? groups : typeof groups === 'string' ? [groups] : [];
}

export function requireLeader(req, res, next) {
  const groupList = getCognitoGroupList(req);
  if (!groupList.includes('leader')) {
    return res.status(403).json({ message: 'Forbidden (Leader only)' });
  }

  next();
}

export function requireManager(req, res, next) {
  const groupList = getCognitoGroupList(req);
  if (!groupList.includes('manager')) {
    return res.status(403).json({ message: 'Forbidden (Manager only)' });
  }
  next();
}

export function requireLeaderOrManager(req, res, next) {
  const groupList = getCognitoGroupList(req);
  if (!groupList.includes('leader') && !groupList.includes('manager')) {
    return res.status(403).json({ message: 'Forbidden (Leader/Manager only)' });
  }
  next();
}
