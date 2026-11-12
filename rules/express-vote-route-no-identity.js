// Test cases for express-vote-route-no-identity. Run: opengrep scan --test rules/
const express = require('express');
const app = express();
const router = express.Router();
const counts = {};

// ruleid: express-vote-route-no-identity
app.post('/api/vote', (req, res) => {
  counts[req.body.contestantId] = (counts[req.body.contestantId] || 0) + 1;
  res.json({ ok: true });
});

// ruleid: express-vote-route-no-identity
router.post('/posts/:id/like', async (req, res) => {
  await db.posts.increment(req.params.id, 'likes');
  res.end();
});

// ruleid: express-vote-route-no-identity
app.put('/rating', handler);

// A vote tied to a token the server issued.
// ok: express-vote-route-no-identity
app.post('/api/vote', (req, res) => {
  const v = voterFromReq(req);
  if (!v) return res.status(401).end();
  res.json({});
});

// ok: express-vote-route-no-identity
app.post('/api/vote', requireAuth, (req, res) => res.json({}));

// ok: express-vote-route-no-identity
app.post('/vote', (req, res) => {
  if (seen.has(req.ip)) return res.status(429).end();
  res.json({});
});

// Admin routes sit behind a login.
// ok: express-vote-route-no-identity
app.post('/api/admin/reset-votes', handler);

// Not a vote: the word only starts the same way.
// ok: express-vote-route-no-identity
app.post('/api/reactivate', handler);

// Reading results, not voting.
// ok: express-vote-route-no-identity
app.get('/api/votes', handler);
