// Sample Node.js/Express implementation for Google Authentication endpoint
// Add this to your existing Express backend

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
// const { OAuth2Client } = require('google-auth-library'); // Optional: for token verification
// const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

/**
 * Google Authentication Endpoint
 * Handles both user registration and login via Google
 * 
 * POST /auth/google
 * Body: { email, fullName, googleId, photoUrl }
 */
router.post('/auth/google', async (req, res) => {
  try {
    const { email, fullName, googleId, photoUrl } = req.body;

    // Validate required fields
    if (!email || !fullName || !googleId) {
      return res.status(400).json({
        message: 'Email, full name, and Google ID are required'
      });
    }

    // Optional: Verify Google ID token for added security
    // Uncomment if you want to verify the token with Google
    /*
    try {
      const ticket = await client.verifyIdToken({
        idToken: req.body.idToken, // Pass idToken from frontend
        audience: process.env.GOOGLE_CLIENT_ID,
      });
      const payload = ticket.getPayload();
      
      // Verify that the Google ID matches
      if (payload.sub !== googleId) {
        return res.status(401).json({ message: 'Invalid Google credentials' });
      }
    } catch (verifyError) {
      return res.status(401).json({ message: 'Google token verification failed' });
    }
    */

    // Check if user already exists with this googleId
    const existingUserByGoogleId = await db.query(
      'SELECT * FROM users WHERE google_id = ?',
      [googleId]
    );

    let user;
    let isNewUser = false;

    if (existingUserByGoogleId.length > 0) {
      // User exists - LOGIN
      user = existingUserByGoogleId[0];
      
      // Update last login timestamp
      await db.query(
        'UPDATE users SET last_login = NOW() WHERE id = ?',
        [user.id]
      );
    } else {
      // Check if email is already registered (regular auth)
      const existingUserByEmail = await db.query(
        'SELECT * FROM users WHERE email = ?',
        [email]
      );

      if (existingUserByEmail.length > 0) {
        // Email exists with regular auth - Link Google account
        user = existingUserByEmail[0];
        
        await db.query(
          'UPDATE users SET google_id = ?, photo_url = ?, last_login = NOW() WHERE id = ?',
          [googleId, photoUrl, user.id]
        );
      } else {
        // New user - REGISTRATION
        isNewUser = true;
        
        // Generate a random password (user won't use it, but DB requires it)
        const randomPassword = await bcrypt.hash(
          Math.random().toString(36).slice(-16),
          10
        );

        const insertResult = await db.query(
          `INSERT INTO users 
           (full_name, email, password, google_id, photo_url, email_verified, created_at) 
           VALUES (?, ?, ?, ?, ?, TRUE, NOW())`,
          [fullName, email, randomPassword, googleId, photoUrl]
        );

        // Fetch the newly created user
        const newUserResult = await db.query(
          'SELECT * FROM users WHERE id = ?',
          [insertResult.insertId]
        );
        
        user = newUserResult[0];
      }
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '30d' }
    );

    // Prepare user response (don't send password)
    const userResponse = {
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      photoUrl: user.photo_url,
      googleId: user.google_id,
      emailVerified: user.email_verified,
      createdAt: user.created_at,
    };

    // Return success response
    return res.status(isNewUser ? 201 : 200).json({
      user: userResponse,
      token: token,
      message: isNewUser 
        ? 'Account created successfully with Google' 
        : 'Logged in successfully with Google'
    });

  } catch (error) {
    console.error('Google auth error:', error);
    return res.status(500).json({
      message: 'Internal server error during Google authentication'
    });
  }
});

module.exports = router;

/**
 * Database Schema Update Required:
 * 
 * ALTER TABLE users ADD COLUMN google_id VARCHAR(255) UNIQUE;
 * ALTER TABLE users ADD COLUMN photo_url VARCHAR(500);
 * ALTER TABLE users MODIFY password VARCHAR(255) NULL; -- If you want to allow Google-only accounts
 * 
 * CREATE INDEX idx_google_id ON users(google_id);
 */

/**
 * Environment Variables Required:
 * 
 * GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
 * JWT_SECRET=your-jwt-secret-key
 */

/**
 * Usage in main app file:
 * 
 * const googleAuthRouter = require('./routes/google_auth_endpoint');
 * app.use('/auth', googleAuthRouter);
 */
