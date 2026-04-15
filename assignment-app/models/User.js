const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3
    },
    passwordHash: {
        type: String,
        required: false // Optional now because of Google SSO
    },
    googleId: {
        type: String,
        required: false,
        unique: true,
        sparse: true // Allows multiple null values
    },
    demoSsoId: {
        type: String,
        required: false,
        unique: true,
        sparse: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('User', userSchema);
