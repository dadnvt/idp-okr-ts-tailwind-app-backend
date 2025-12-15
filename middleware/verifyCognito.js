import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

const client = jwksClient({
  jwksUri:
    'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ilPTEVT0U/.well-known/jwks.json',
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
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
