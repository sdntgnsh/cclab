require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');
const User = require('./models/User');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Database Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB Atlas'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// Routes
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
