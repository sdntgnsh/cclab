require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const IdpUser = require('./IdpUser');

const app = express();

const PORT = process.env.SSO_PORT || 4000;
const ISSUER = process.env.SSO_ISSUER || `http://localhost:${PORT}`;
const CLIENTS = new Map(
  (process.env.SSO_CLIENTS || 'assignment-app:dev-secret')
    .split(',')
    .map(pair => pair.trim())
    .filter(Boolean)
    .map(pair => {
      const [id, secret] = pair.split(':');
      return [id, secret || ''];
    })
);

// In-memory stores (fine for demo)
const sessions = new Map(); // sid -> { username, createdAt }
const authCodes = new Map(); // code -> { username, client_id, redirect_uri, exp }

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

function randomId(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

// Database Connection (reuse your existing Atlas connection string)
// Required on the IdP:
//   MONGODB_URI="..."
mongoose
  .connect((process.env.MONGODB_URI || '').trim())
  .then(() => console.log('✅ IdP connected to MongoDB Atlas'))
  .catch(err => console.error('❌ IdP MongoDB Connection Error:', err));

function htmlPage(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    :root { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; }
    body { background:#0b1220; color:#e5e7eb; margin:0; padding:32px; }
    .card { max-width:520px; margin:0 auto; background:#111a2e; border:1px solid #24324f; border-radius:16px; padding:20px; }
    input { width:100%; padding:12px 12px; border-radius:10px; border:1px solid #2b3a5e; background:#0b1220; color:#e5e7eb; }
    label { display:block; margin:12px 0 6px; color:#cbd5e1; }
    button { width:100%; padding:12px; border-radius:10px; border:0; background:#4f46e5; color:white; font-weight:600; cursor:pointer; margin-top:14px; }
    .muted { color:#94a3b8; font-size: 13px; margin-top: 10px; }
    .err { color:#fca5a5; margin-top:10px; }
    code { background:#0b1220; padding:2px 6px; border-radius:8px; border:1px solid #24324f; }
  </style>
</head>
<body>
  <div class="card">
    ${body}
    <p class="muted">Demo SSO Provider (IdP) — issuer: <code>${ISSUER}</code></p>
  </div>
</body>
</html>`;
}

function getSession(req) {
  const sid = req.cookies.idp_session;
  if (!sid) return null;
  return sessions.get(sid) || null;
}

function requireValidClient(req, res) {
  const { client_id, redirect_uri } = req.query;
  if (!client_id || !redirect_uri) {
    res.status(400).send('Missing client_id or redirect_uri');
    return null;
  }
  if (!CLIENTS.has(client_id)) {
    res.status(400).send('Unknown client_id');
    return null;
  }
  // For demo simplicity we trust redirect_uri; in real SSO you must pre-register and match exact URIs.
  return { client_id, redirect_uri };
}

app.get('/', (req, res) => {
  res.send(
    htmlPage(
      'Demo SSO Provider',
      `<h2 style="margin:0 0 8px;">Demo SSO Provider</h2>
       <p class="muted" style="margin:0 0 14px;">Use <code>/oauth/authorize</code> from the app to start SSO.</p>
       <p class="muted" style="margin:0;">Users come from IdP registration (MongoDB).</p>`
    )
  );
});

app.get('/oauth/authorize', (req, res) => {
  const client = requireValidClient(req, res);
  if (!client) return;

  const { state = '', scope = 'basic' } = req.query;
  const sess = getSession(req);
  if (sess) {
    // Issue auth code and redirect back
    const code = randomId(18);
    authCodes.set(code, {
      username: sess.username,
      client_id: client.client_id,
      redirect_uri: client.redirect_uri,
      exp: Date.now() + 2 * 60 * 1000 // 2 minutes
    });
    const redirect = new URL(client.redirect_uri);
    redirect.searchParams.set('code', code);
    if (state) redirect.searchParams.set('state', state);
    res.redirect(redirect.toString());
    return;
  }

  // Not logged in: show login form
  const form = htmlPage(
    'Login - Demo SSO',
    `<h2 style="margin:0 0 8px;">Sign in to Demo SSO</h2>
     <p class="muted" style="margin:0 0 14px;">Client: <code>${client.client_id}</code> • Scope: <code>${scope}</code></p>
     <form method="POST" action="/login">
       <input type="hidden" name="client_id" value="${client.client_id}" />
       <input type="hidden" name="redirect_uri" value="${encodeURIComponent(client.redirect_uri)}" />
       <input type="hidden" name="state" value="${encodeURIComponent(state)}" />
       <label>Username</label>
       <input name="username" autocomplete="username" required />
       <label>Password</label>
       <input name="password" type="password" autocomplete="current-password" required />
       <button type="submit">Sign in</button>
     </form>`
     +
     `<p class="muted" style="margin-top:12px;">No IdP account yet?
        <a style="color:#a5b4fc" href="/register?client_id=${encodeURIComponent(client.client_id)}&redirect_uri=${encodeURIComponent(client.redirect_uri)}&state=${encodeURIComponent(state)}">Register</a>
      </p>`
  );
  res.send(form);
});

app.post('/login', async (req, res) => {
  const { username = '', password = '', client_id = '', redirect_uri = '', state = '' } = req.body;

  if (!CLIENTS.has(client_id)) {
    res.status(400).send('Unknown client_id');
    return;
  }

  const decodedRedirect = decodeURIComponent(redirect_uri || '');
  const decodedState = decodeURIComponent(state || '');

  const idpUser = await IdpUser.findOne({ username: String(username).trim() });
  const ok = idpUser ? await bcrypt.compare(String(password), idpUser.passwordHash) : false;
  if (!ok) {
    res.status(401).send(
      htmlPage(
        'Login failed',
        `<h2 style="margin:0 0 8px;">Login failed</h2>
         <p class="err">Invalid username or password.</p>
         <p class="muted"><a style="color:#a5b4fc" href="/oauth/authorize?client_id=${encodeURIComponent(
           client_id
         )}&redirect_uri=${encodeURIComponent(decodedRedirect)}&state=${encodeURIComponent(decodedState)}">Try again</a></p>`
      )
    );
    return;
  }

  const sid = randomId(18);
  sessions.set(sid, { username, createdAt: Date.now() });
  res.cookie('idp_session', sid, { httpOnly: true, sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000 });

  // Continue authorization
  const url = new URL('/oauth/authorize', ISSUER);
  url.searchParams.set('client_id', client_id);
  url.searchParams.set('redirect_uri', decodedRedirect);
  if (decodedState) url.searchParams.set('state', decodedState);
  res.redirect(url.toString());
});

app.get('/register', (req, res) => {
  const client = requireValidClient(req, res);
  if (!client) return;
  const { state = '' } = req.query;

  res.send(
    htmlPage(
      'Register - Demo SSO',
      `<h2 style="margin:0 0 8px;">Create IdP account</h2>
       <p class="muted" style="margin:0 0 14px;">This account is used to sign in via Demo SSO.</p>
       <form method="POST" action="/register">
         <input type="hidden" name="client_id" value="${client.client_id}" />
         <input type="hidden" name="redirect_uri" value="${encodeURIComponent(client.redirect_uri)}" />
         <input type="hidden" name="state" value="${encodeURIComponent(state)}" />
         <label>Username</label>
         <input name="username" autocomplete="username" minlength="3" required />
         <label>Password</label>
         <input name="password" type="password" autocomplete="new-password" minlength="6" required />
         <button type="submit">Register</button>
       </form>
       <p class="muted" style="margin-top:12px;">
         Already have an account?
         <a style="color:#a5b4fc" href="/oauth/authorize?client_id=${encodeURIComponent(
           client.client_id
         )}&redirect_uri=${encodeURIComponent(client.redirect_uri)}&state=${encodeURIComponent(state)}">Back to login</a>
       </p>`
    )
  );
});

app.post('/register', async (req, res) => {
  const { username = '', password = '', client_id = '', redirect_uri = '', state = '' } = req.body;
  if (!CLIENTS.has(client_id)) {
    res.status(400).send('Unknown client_id');
    return;
  }

  const decodedRedirect = decodeURIComponent(redirect_uri || '');
  const decodedState = decodeURIComponent(state || '');

  const cleanUsername = String(username).trim();
  if (cleanUsername.length < 3) {
    res.status(400).send(htmlPage('Register failed', `<h2 style="margin:0 0 8px;">Register failed</h2><p class="err">Username too short.</p>`));
    return;
  }
  if (String(password).length < 6) {
    res.status(400).send(htmlPage('Register failed', `<h2 style="margin:0 0 8px;">Register failed</h2><p class="err">Password too short.</p>`));
    return;
  }

  try {
    const existing = await IdpUser.findOne({ username: cleanUsername });
    if (existing) {
      res.status(409).send(
        htmlPage(
          'Register failed',
          `<h2 style="margin:0 0 8px;">Register failed</h2>
           <p class="err">Username already exists.</p>
           <p class="muted"><a style="color:#a5b4fc" href="/register?client_id=${encodeURIComponent(
             client_id
           )}&redirect_uri=${encodeURIComponent(decodedRedirect)}&state=${encodeURIComponent(decodedState)}">Try another</a></p>`
        )
      );
      return;
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(String(password), salt);
    await new IdpUser({ username: cleanUsername, passwordHash }).save();

    // After register, take them back to login/authorize
    const url = new URL('/oauth/authorize', ISSUER);
    url.searchParams.set('client_id', client_id);
    url.searchParams.set('redirect_uri', decodedRedirect);
    if (decodedState) url.searchParams.set('state', decodedState);
    res.redirect(url.toString());
  } catch (err) {
    console.error(err);
    res.status(500).send(htmlPage('Register failed', `<h2 style="margin:0 0 8px;">Register failed</h2><p class="err">Server error.</p>`));
  }
});

app.post('/oauth/token', (req, res) => {
  const { code, client_id, client_secret, redirect_uri } = req.body || {};
  if (!code || !client_id || !client_secret || !redirect_uri) {
    return res.status(400).json({ error: 'invalid_request' });
  }
  const expected = CLIENTS.get(client_id);
  if (!expected || expected !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  const record = authCodes.get(code);
  if (!record) return res.status(400).json({ error: 'invalid_grant' });
  if (record.exp < Date.now()) {
    authCodes.delete(code);
    return res.status(400).json({ error: 'expired_code' });
  }
  if (record.client_id !== client_id) return res.status(400).json({ error: 'invalid_grant' });
  if (record.redirect_uri !== redirect_uri) return res.status(400).json({ error: 'redirect_uri_mismatch' });

  authCodes.delete(code);

  // Return a minimal "ID token"-like payload (not JWT, just JSON for demo)
  const username = record.username;
  return res.json({
    issuer: ISSUER,
    sub: `demo|${username}`,
    preferred_username: username
  });
});

app.post('/logout', (req, res) => {
  const sid = req.cookies.idp_session;
  if (sid) sessions.delete(sid);
  res.clearCookie('idp_session');
  res.redirect('/');
});

app.listen(PORT, () => {
  console.log(`🔐 Demo SSO Provider running at ${ISSUER}`);
});

