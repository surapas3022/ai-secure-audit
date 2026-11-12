// Test cases for express-route-no-rate-limit. Run: opengrep scan --test rules/
const express = require('express');
const app = express();
const router = express.Router();

// ruleid: express-route-no-rate-limit
app.post('/api/admin/login', (req, res) => {
  if (req.body.password !== process.env.ADMIN_PASSWORD) return res.status(401).end();
  res.json({ ok: true });
});

// ruleid: express-route-no-rate-limit
app.post('/api/join', (req, res) => {
  res.json({ token: newToken() });
});

// ruleid: express-route-no-rate-limit
router.post('/register', async (req, res) => {
  await saveUser(req.body);
  res.json({ ok: true });
});

// ruleid: express-route-no-rate-limit
app.put('/auth/reset-password', handler);

// ruleid: express-route-no-rate-limit
userRouter.post('/sign-up', handler);

// ok: express-route-no-rate-limit
app.post('/api/join', loginLimiter, (req, res) => res.json({}));

// ok: express-route-no-rate-limit
app.post('/api/vote', rateLimit({ windowMs: 60000, max: 10 }), handler);

// ok: express-route-no-rate-limit
app.post('/api/join', (req, res) => {
  const wait = limits.joinIp.wait(req.ip);
  if (wait) return limited(res, wait);
  res.json({});
});

// ok: express-route-no-rate-limit
app.post('/api/admin/login', (req, res) => {
  if (tooManyAttempts(req.ip)) return res.status(429).end();
  res.json({});
});

// Not a sign-in, join or sign-up route.
// ok: express-route-no-rate-limit
app.post('/api/admin/topics', handler);

// Admin routes behind a login, even when the path says reset or join.
// ok: express-route-no-rate-limit
app.post('/api/admin/reset-votes', handler);

// A vote needs a token from /api/join; the join route is what must be limited.
// ok: express-route-no-rate-limit
app.post('/api/vote', handler);

// Reading, not submitting.
// ok: express-route-no-rate-limit
app.get('/login', (req, res) => res.sendFile('login.html'));

// An outgoing request, not a route.
// ok: express-route-no-rate-limit
axios.post('/api/login', { user, password });
