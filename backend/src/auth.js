import jwt from 'jsonwebtoken';

function secret() {
  const s = process.env.JWT_SECRET;
  if (!s) throw new Error('JWT_SECRET is not set');
  return s;
}

export function signAdminToken(admin) {
  return jwt.sign(
    { sub: admin.id, email: admin.email, name: admin.name },
    secret(),
    { expiresIn: '7d' }
  );
}

export function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.admin = jwt.verify(token, secret());
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
