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
