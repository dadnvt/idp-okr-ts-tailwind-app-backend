import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

function getCognitoConfig() {
  const region = process.env.AWS_REGION || process.env.COGNITO_REGION || 'us-east-1';
  const userPoolId = process.env.COGNITO_USER_POOL_ID || process.env.AWS_COGNITO_USER_POOL_ID || 'us-east-1_ilPTEVT0U';
  const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
  const jwksUri = `${issuer}/.well-known/jwks.json`;
  return { region, userPoolId, issuer, jwksUri };
}

const { issuer, jwksUri } = getCognitoConfig();

const client = jwksClient({
  jwksUri,
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
      issuer,
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
