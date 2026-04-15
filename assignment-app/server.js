require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('./models/User');
const http = require('http');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

// Passport Configuration
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://35.190.176.176.nip.io/auth/google/callback" // Must match Google Cloud exactly
  },
  async function(accessToken, refreshToken, profile, cb) {
      try {
          // Check if user already exists
          let user = await User.findOne({ googleId: profile.id });
          
          if (!user) {
              // Create a unique username safely
              let baseUsername = profile.emails && profile.emails.length > 0
                ? profile.emails[0].value.split('@')[0]
                : profile.displayName.replace(/\s+/g, '').toLowerCase();
              let username = baseUsername;
              let counter = 1;
              while (await User.findOne({ username })) {
                  username = `${baseUsername}${counter}`;
                  counter++;
              }
              
              // Create new user
              user = new User({
                  username: username,
                  googleId: profile.id
              });
              await user.save();
          }
          return cb(null, user);
      } catch (err) {
          return cb(err, null);
      }
  }
));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

function postJson(urlString, bodyObj) {
    return new Promise((resolve, reject) => {
        const url = new URL(urlString);
        const data = JSON.stringify(bodyObj);
        const isHttps = url.protocol === 'https:';
        const req = (isHttps ? https : http).request({
            method: 'POST',
            hostname: url.hostname,
            port: url.port || (isHttps ? 443 : 80),
            path: url.pathname + (url.search || ''),
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data)
            }
        }, (res) => {
            let raw = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => raw += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(raw || '{}');
                    resolve({ status: res.statusCode || 0, json: parsed });
                } catch (e) {
                    reject(new Error(`Failed to parse JSON response (${res.statusCode}): ${raw}`));
                }
            });
        });
        req.on('error', reject);
        req.write(data);
        req.end();
    });
}

// Database Connection
mongoose.connect(process.env.MONGODB_URI.trim())
.then(() => console.log('✅ Connected to MongoDB Atlas'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// Routes

// --- Google OAuth Routes ---
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'], session: false })
);

app.get('/auth/google/callback', 
  passport.authenticate('google', { session: false, failureRedirect: '/index.html' }),
  function(req, res) {
    // Successful authentication, issue cookie similar to normal login
    res.cookie('user', req.user.username, { 
        httpOnly: false,
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    });
    res.redirect('/dashboard.html');
  }
);

// --- Demo SSO (Custom IdP) Routes ---
// Env needed on the app (SP):
//   SSO_PROVIDER_BASE=http://<host>:4000
//   SSO_CLIENT_ID=assignment-app
//   SSO_CLIENT_SECRET=dev-secret
//   SSO_CALLBACK_URL=http://<your-app-host>/auth/demo-sso/callback
app.get('/auth/demo-sso', (req, res) => {
    const providerBase = process.env.SSO_PROVIDER_BASE || 'http://localhost:4000';
    const clientId = process.env.SSO_CLIENT_ID || 'assignment-app';
    const callbackUrl = process.env.SSO_CALLBACK_URL || `http://localhost:${PORT}/auth/demo-sso/callback`;

    const state = Math.random().toString(36).slice(2);
    res.cookie('demo_sso_state', state, { httpOnly: true, sameSite: 'lax', maxAge: 5 * 60 * 1000 });

    const authorize = new URL('/oauth/authorize', providerBase);
    authorize.searchParams.set('client_id', clientId);
    authorize.searchParams.set('redirect_uri', callbackUrl);
    authorize.searchParams.set('state', state);
    authorize.searchParams.set('scope', 'basic');
    res.redirect(authorize.toString());
});

app.get('/auth/demo-sso/callback', async (req, res) => {
    try {
        const { code, state } = req.query;
        const expectedState = req.cookies.demo_sso_state;
        res.clearCookie('demo_sso_state');

        if (!code || !state || !expectedState || state !== expectedState) {
            return res.redirect('/index.html');
        }

        const providerBase = process.env.SSO_PROVIDER_BASE || 'http://localhost:4000';
        const clientId = process.env.SSO_CLIENT_ID || 'assignment-app';
        const clientSecret = process.env.SSO_CLIENT_SECRET || 'dev-secret';
        const callbackUrl = process.env.SSO_CALLBACK_URL || `http://localhost:${PORT}/auth/demo-sso/callback`;

        const tokenUrl = new URL('/oauth/token', providerBase).toString();
        const { status, json } = await postJson(tokenUrl, {
            code,
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uri: callbackUrl
        });

        if (status < 200 || status >= 300) {
            return res.redirect('/index.html');
        }

        const ssoSub = json.sub;
        const preferred = json.preferred_username;
        if (!ssoSub || !preferred) {
            return res.redirect('/index.html');
        }

        let user = await User.findOne({ demoSsoId: ssoSub });
        if (!user) {
            // Create a unique username safely
            let baseUsername = String(preferred).replace(/[^a-zA-Z0-9_]/g, '').toLowerCase() || 'user';
            let username = baseUsername;
            let counter = 1;
            while (await User.findOne({ username })) {
                username = `${baseUsername}${counter}`;
                counter++;
            }

            user = new User({
                username,
                demoSsoId: ssoSub
            });
            await user.save();
        }

        res.cookie('user', user.username, {
            httpOnly: false,
            maxAge: 24 * 60 * 60 * 1000
        });
        return res.redirect('/dashboard.html');
    } catch (err) {
        console.error(err);
        return res.redirect('/index.html');
    }
});

// 1. Register
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Check if user exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already taken' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        // Create user
        const newUser = new User({
            username,
            passwordHash
        });

        await newUser.save();

        // Create session cookie
        res.cookie('user', newUser.username, { 
            httpOnly: false, // In production, make true for security
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        });

        res.status(201).json({ message: 'User registered successfully', username: newUser.username });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// 2. Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Create session cookie
        res.cookie('user', user.username, { 
            httpOnly: false,
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        });

        res.status(200).json({ message: 'Login successful', username: user.username });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// 3. Logout
app.post('/api/logout', (req, res) => {
    res.clearCookie('user');
    res.status(200).json({ message: 'Logged out successfully' });
});

// 4. Get all users (for dashboard)
app.get('/api/users', async (req, res) => {
    try {
        // Optional: Require user to be logged in to see this
        const currentUser = req.cookies.user;
        if (!currentUser) {
            return res.status(401).json({ error: 'Unauthorized. Please login.' });
        }

        // Exclude passwords from result
        const users = await User.find({}, { passwordHash: 0 }).sort({ createdAt: -1 });
        res.status(200).json(users);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error fetching users' });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
