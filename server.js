require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const stream = require('stream');
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const pool = require('./db');

const app = express();
app.use(express.json());
app.use(cors()); // Enable CORS for local development

// Health check endpoint for monitoring services (e.g., UptimeRobot)
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.status(200).json({ 
    message: 'Para Backend API',
    version: '1.0.0',
    status: 'running'
  });
});

// Middleware to authenticate JWT token (optional for chat endpoints)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Middleware to optionally authenticate JWT token (for chat endpoints)
// If token is provided, verify it and attach user info
// If not provided, req.user will be undefined (for backward compatibility)
const optionalAuthenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) {
        req.user = user;
      }
      // Continue even if token is invalid (for backward compatibility)
      next();
    });
  } else {
    next();
  }
};

// MySQL connection pool imported from db.js

const JWT_SECRET = process.env.JWT_SECRET || 'a3f0b2a7e1f84d5f1d3a9e63e9c4e2d8a5f7b6d0c9e3f1b4a1c2e3d4b5f6a7c8';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'b5c2a8d4f9e7b1a6d2e3c7f8a9b4c6d5f0a1b2e3c4d5e6f7a8b9c0d1e2f3a4'; // Should be 32+ chars

if (!process.env.JWT_SECRET || !process.env.ENCRYPTION_KEY) {
  console.warn('⚠️  WARNING: Using default secrets. Set JWT_SECRET and ENCRYPTION_KEY environment variables in production!');
}

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 30; // Lock account for 30 minutes after max attempts

// Helper function to get encryption key for MySQL
function getEncryptionKeyQuery() {
  return `UNHEX(SHA2('${ENCRYPTION_KEY}', 256))`;
}

// Helper function to generate UUID v4
function generateUUID() {
  return crypto.randomUUID ? crypto.randomUUID() : 
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
}

// Helper function to convert UUID string to binary buffer for MySQL
function uuidToBinary(uuid) {
  if (Buffer.isBuffer(uuid)) return uuid;
  
  // Remove dashes and convert hex string to binary
  const hex = uuid.replace(/-/g, '');
  return Buffer.from(hex, 'hex');
}

// Helper function to convert binary UUID to string
function binaryToUuid(binUuid) {
  if (!binUuid) return null;
  if (typeof binUuid === 'string') return binUuid; // Already a string
  
  // If it's a buffer, convert to hex string with dashes
  let hex;
  if (Buffer.isBuffer(binUuid)) {
    hex = binUuid.toString('hex');
  } else {
    // Might be a mysql2 binary type
    hex = binUuid.hex || binUuid.toString('hex');
  }
  
  if (hex.length === 32) {
    return `${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20,32)}`;
  }
  return hex;
}

// Helper function to format user object for API responses
function formatUserResponse(user) {
  const userUuid = binaryToUuid(user.id);
  const isSocialLogin = !!(user.google_id || user.facebook_id);
  
  return {
    id: userUuid,
    fullName: user.full_name,
    email: user.email,
    avatarUrl: user.avatar_url || user.photo_url || null,
    emailVerified: user.email_verified || false,
    twoFactorEnabled: user.two_factor_enabled || false,
    isSocialLogin: isSocialLogin,
    googleId: user.google_id || null,
    facebookId: user.facebook_id || null,
  };
}

// =============================
// Cloudinary configuration
// =============================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || '',
  api_key: process.env.CLOUDINARY_API_KEY || '',
  api_secret: process.env.CLOUDINARY_API_SECRET || '',
});

// Multer in-memory storage
const upload = multer({ storage: multer.memoryStorage() });

// =============================
// Email configuration (nodemailer)
// =============================
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.EMAIL_PORT || '587'),
  secure: process.env.EMAIL_SECURE === 'true', // true for port 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
  connectionTimeout: 30000, // 30 seconds
  greetingTimeout: 15000,   // 15 seconds
  socketTimeout: 30000,     // 30 seconds
  debug: true,              // Enable debug output
  logger: true,             // Log to console
});

function buildResetHtml({
  title,
  emoji,
  message,
  buttonLabel,
  buttonHref,
  redirectHref,
}) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>${title}</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; margin: 0; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; }
        .container { background: rgba(255,255,255,0.1); padding: 40px; border-radius: 20px; backdrop-filter: blur(10px); max-width: 520px; }
        .icon { font-size: 64px; margin-bottom: 20px; }
        h1 { margin-bottom: 20px; font-size: 32px; }
        p { margin-bottom: 30px; font-size: 18px; opacity: 0.9; }
        .button { display: inline-block; padding: 15px 30px; background: white; color: #667eea; text-decoration: none; border-radius: 10px; font-weight: 600; font-size: 16px; margin: 10px; transition: all 0.3s ease; }
        .button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0,0,0,0.2); }
        .countdown { margin-top: 20px; font-size: 14px; opacity: 0.8; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="icon">${emoji}</div>
        <h1>${title}</h1>
        <p>${message}</p>
        <a href="${buttonHref}" class="button">${buttonLabel}</a>
        ${redirectHref ? `<div class="countdown" id="countdown">Redirecting in 5 seconds...</div>` : ''}
      </div>
      ${redirectHref ? `
      <script>
        let countdown = 5;
        const countdownEl = document.getElementById('countdown');
        const timer = setInterval(() => {
          countdown--;
          if (countdownEl) {
            countdownEl.textContent = 'Redirecting in ' + countdown + ' seconds...';
          }
          if (countdown <= 0) {
            clearInterval(timer);
            window.location.href = '${redirectHref}';
          }
        }, 1000);
      </script>` : ''}
    </body>
    </html>
  `;
}

// Function to send verification email
async function sendVerificationEmail(email, fullName, verificationToken) {
  // Use deep link for mobile app: paraapp://verify-email?token=xxx
  // Falls back to web URL if FRONTEND_URL is set
  const verificationUrl = `${process.env.FRONTEND_URL || 'paraapp://verify-email'}?token=${verificationToken}`;
  
  // Try SendGrid API first if configured, fallback to SMTP
  if (process.env.EMAIL_HOST === 'smtp.sendgrid.net' && process.env.EMAIL_USER === 'apikey') {
    return await sendVerificationEmailViaSendGridAPI(email, fullName, verificationToken);
  }
  
  const mailOptions = {
    from: `"${process.env.EMAIL_FROM_NAME || 'Para App'}" <${process.env.EMAIL_FROM_ADDRESS || process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Verify Your Email Address - Para App',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f4f4f4; margin: 0; padding: 0; }
          .container { max-width: 600px; margin: 20px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 20px; text-align: center; }
          .header h1 { color: white; margin: 0; font-size: 28px; }
          .content { padding: 40px 30px; }
          .content h2 { color: #333; margin-top: 0; }
          .content p { color: #666; margin: 15px 0; }
          .button { display: inline-block; padding: 14px 32px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 8px; font-weight: 600; margin: 20px 0; }
          .button:hover { opacity: 0.9; }
          .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #999; font-size: 12px; }
          .token-box { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0; font-family: monospace; word-break: break-all; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎉 Welcome to Para!</h1>
          </div>
          <div class="content">
            <h2>Hi ${fullName},</h2>
            <p>Thank you for signing up! We're excited to have you on board.</p>
            <p>To complete your registration and unlock all features, please verify your email address by clicking the button below:</p>
            <div style="text-align: center;">
              <a href="${verificationUrl}" class="button">Verify Email Address</a>
            </div>
            <p style="margin-top: 30px;">Or copy and paste this link into your browser:</p>
            <div class="token-box">${verificationUrl}</div>
            <p><strong>This link will expire in 24 hours.</strong></p>
            <p>If you didn't create an account with Para, you can safely ignore this email.</p>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} Para App. All rights reserved.</p>
            <p>This is an automated email. Please do not reply.</p>
          </div>
        </div>
      </body>
      </html>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`✅ Verification email sent to ${email}`);
    return true;
  } catch (error) {
    console.error('❌ Error sending verification email:', error);
    return false;
  }
}

// SendGrid API fallback function
async function sendVerificationEmailViaSendGridAPI(email, fullName, verificationToken) {
  const sgMail = require('@sendgrid/mail');
  sgMail.setApiKey(process.env.EMAIL_PASSWORD);
  
  const verificationUrl = `https://para-backend-eukj.onrender.com/api/auth/verify-email/${verificationToken}?redirect=paraapp://verify-email`;
  
  const msg = {
    to: email,
    from: {
      email: process.env.EMAIL_FROM_ADDRESS || 'support-app.online',
      name: process.env.EMAIL_FROM_NAME || 'Para App'
    },
    subject: 'Verify Your Email Address - Para App',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f4f4f4; margin: 0; padding: 0; }
          .container { max-width: 600px; margin: 20px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 20px; text-align: center; }
          .header h1 { color: white; margin: 0; font-size: 28px; }
          .content { padding: 40px 30px; }
          .content h2 { color: #333; margin-top: 0; }
          .content p { color: #666; margin: 15px 0; }
          .button { display: inline-block; padding: 14px 32px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 8px; font-weight: 600; margin: 20px 0; }
          .button:hover { opacity: 0.9; }
          .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #999; font-size: 12px; }
          .token-box { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0; font-family: monospace; word-break: break-all; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎉 Welcome to Para!</h1>
          </div>
          <div class="content">
            <h2>Hi ${fullName},</h2>
            <p>Thank you for signing up! We're excited to have you on board.</p>
            <p>To complete your registration and unlock all features, please verify your email address by clicking the button below:</p>
            <div style="text-align: center;">
              <a href="${verificationUrl}" class="button">Verify Email Address</a>
            </div>
            <p style="margin-top: 30px;">Or copy and paste this link into your browser:</p>
            <div class="token-box">${verificationUrl}</div>
            <p><strong>This link will expire in 24 hours.</strong></p>
            <p>If you didn't create an account with Para, you can safely ignore this email.</p>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} Para App. All rights reserved.</p>
            <p>This is an automated email. Please do not reply.</p>
          </div>
        </div>
      </body>
      </html>
    `,
  };

  try {
    await sgMail.send(msg);
    console.log(`✅ Verification email sent via SendGrid API to ${email}`);
    return true;
  } catch (error) {
    console.error('❌ Error sending via SendGrid API:', error.response?.body || error);
    return false;
  }
}

// Ensure users table has avatar_url column (idempotent)
async function ensureAvatarColumn() {
  try {
    const [rows] = await pool.execute(
      `SELECT COUNT(*) AS cnt FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'avatar_url'`
    );
    if (rows[0].cnt === 0) {
      await pool.execute(`ALTER TABLE users ADD COLUMN avatar_url VARCHAR(512) NULL AFTER email`);
      console.log('✅ Added users.avatar_url column');
    }
  } catch (err) {
    console.error('Error ensuring avatar_url column:', err.message);
  }
}

// Registration endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    // Validate input
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Check if user exists (decrypt email for comparison)
    const encryptionKey = getEncryptionKeyQuery();
    const [existing] = await pool.execute(
      `SELECT id FROM users WHERE CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) = ?`,
      [email]
    );

    if (existing.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Generate UUID in Node.js and convert to binary
    const userId = generateUUID();
    const userIdBinary = uuidToBinary(userId);

    // Insert user with binary UUID
    const [result] = await pool.execute(
      `INSERT INTO users (id, full_name, email, avatar_url, password_hash) 
       VALUES (?, AES_ENCRYPT(?, ${encryptionKey}), AES_ENCRYPT(?, ${encryptionKey}), NULL, ?)`,
      [userIdBinary, fullName, email, hashedPassword]
    );

    // Return the created user with decrypted data
    const [newUser] = await pool.execute(
      `SELECT 
        id,
        CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) as full_name,
        CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email
       FROM users 
       WHERE CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) = ?`,
      [email]
    );

    // Convert binary UUID to string
    const userUuid = binaryToUuid(newUser[0].id);

    res.status(201).json({
      message: 'User created successfully!',
      user: {
        id: userUuid,
        fullName: newUser[0].full_name,
        email: newUser[0].email,
        avatarUrl: null
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const encryptionKey = getEncryptionKeyQuery();
    
    // Get user with decrypted email and name
    const [users] = await pool.execute(
      `SELECT 
        id,
        CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) as full_name,
        CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email,
        avatar_url,
        email_verified,
        password_hash,
        old_password_hash,
        password_changed_at,
        two_factor_enabled,
        google_id,
        facebook_id,
        is_locked,
        failed_login_attempts,
        locked_until,
        last_login_attempt
       FROM users 
       WHERE CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) = ?`,
      [email]
    );

    if (users.length === 0) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const user = users[0];
    const now = new Date();
    const userUuid = binaryToUuid(user.id); // Convert binary UUID to string
    const userIdBinary = uuidToBinary(userUuid); // For database operations

    // Check if account is locked
    if (user.is_locked) {
      if (user.locked_until && new Date(user.locked_until) > now) {
        const minutesLeft = Math.ceil((new Date(user.locked_until) - now) / 60000);
        return res.status(423).json({ 
          message: `Account is locked. Try again in ${minutesLeft} minute(s).`,
          lockedUntil: user.locked_until
        });
      } else {
        // Lock expired, unlock the account
        await pool.execute(
          'UPDATE users SET is_locked = 0, failed_login_attempts = 0, locked_until = NULL WHERE id = ?',
          [userIdBinary]
        );
      }
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    
    if (!isMatch) {
      // Check if user is trying to use their old password
      let isOldPassword = false;
      let passwordChangedMessage = '';
      
      if (user.old_password_hash && user.password_changed_at) {
        isOldPassword = await bcrypt.compare(password, user.old_password_hash);
        
        if (isOldPassword) {
          // Calculate time since password change
          const changedAt = new Date(user.password_changed_at);
          const timeDiff = now - changedAt;
          const daysAgo = Math.floor(timeDiff / (1000 * 60 * 60 * 24));
          const hoursAgo = Math.floor(timeDiff / (1000 * 60 * 60));
          const minutesAgo = Math.floor(timeDiff / (1000 * 60));
          
          let timeAgoText;
          if (daysAgo > 0) {
            timeAgoText = daysAgo === 1 ? '1 day ago' : `${daysAgo} days ago`;
          } else if (hoursAgo > 0) {
            timeAgoText = hoursAgo === 1 ? '1 hour ago' : `${hoursAgo} hours ago`;
          } else if (minutesAgo > 0) {
            timeAgoText = minutesAgo === 1 ? '1 minute ago' : `${minutesAgo} minutes ago`;
          } else {
            timeAgoText = 'just now';
          }
          
          passwordChangedMessage = `Your password was changed ${timeAgoText}. Please use your new password.`;
        }
      }
      
      // Increment failed login attempts
      const newAttempts = (user.failed_login_attempts || 0) + 1;
      const shouldLock = newAttempts >= MAX_FAILED_ATTEMPTS;
      const lockUntil = shouldLock 
        ? new Date(now.getTime() + LOCKOUT_DURATION_MINUTES * 60000)
        : null;

      await pool.execute(
        `UPDATE users 
         SET failed_login_attempts = ?, 
             is_locked = ?,
             locked_until = ?,
             last_login_attempt = ?
         WHERE id = ?`,
        [newAttempts, shouldLock ? 1 : 0, lockUntil, now, userIdBinary]
      );

      if (shouldLock) {
        return res.status(423).json({ 
          message: `Account has been locked due to ${MAX_FAILED_ATTEMPTS} failed login attempts. Try again in ${LOCKOUT_DURATION_MINUTES} minutes.`,
          lockedUntil: lockUntil,
          isOldPassword: isOldPassword,
          passwordChangedMessage: passwordChangedMessage
        });
      }

      const remainingAttempts = MAX_FAILED_ATTEMPTS - newAttempts;
      
      // Build the error message
      let errorMessage = 'Invalid credentials.';
      if (isOldPassword && passwordChangedMessage) {
        errorMessage = passwordChangedMessage;
      }
      errorMessage += ` ${newAttempts} failed attempt${newAttempts > 1 ? 's' : ''}. ${remainingAttempts} attempt${remainingAttempts > 1 ? 's' : ''} remaining before account lock.`;
      
      return res.status(400).json({ 
        message: errorMessage,
        isOldPassword: isOldPassword,
        passwordChangedMessage: passwordChangedMessage,
        failedAttempts: newAttempts,
        remainingAttempts: remainingAttempts
      });
    }

    // Successful login - reset failed attempts and update last login
    await pool.execute(
      'UPDATE users SET failed_login_attempts = 0, is_locked = 0, locked_until = NULL, last_login_attempt = ? WHERE id = ?',
      [now, userIdBinary]
    );

    // Check if 2FA is enabled
    if (user.two_factor_enabled) {
      // Don't generate full token yet, return partial response requiring 2FA
      return res.json({
        message: '2FA verification required',
        requires2FA: true,
        userId: userUuid,
        user: formatUserResponse(user)
      });
    }

    // Generate token using UUID string (only if 2FA is not enabled)
    const token = jwt.sign(
      { userId: userUuid, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: formatUserResponse(user)
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Facebook authentication endpoint (handles both login and registration)
app.post('/api/auth/facebook', async (req, res) => {
  try {
    const { email, fullName, facebookId, photoUrl } = req.body;

    // Validate required fields
    if (!email || !fullName || !facebookId) {
      return res.status(400).json({
        message: 'Email, full name, and Facebook ID are required'
      });
    }

    const encryptionKey = getEncryptionKeyQuery();
    const now = new Date();

    // Check if user already exists with this facebookId
    const [existingUserByFacebookId] = await pool.execute(
      'SELECT id FROM users WHERE facebook_id = ?',
      [facebookId]
    );

    let user;
    let isNewUser = false;
    let userIdBinary;

    if (existingUserByFacebookId.length > 0) {
      // User exists with Facebook ID - LOGIN
      userIdBinary = existingUserByFacebookId[0].id;
      
      // Update last login timestamp
      await pool.execute(
        'UPDATE users SET last_login_attempt = ? WHERE id = ?',
        [now, userIdBinary]
      );

      // Get full user details including 2FA status
      const [userDetails] = await pool.execute(
        `SELECT 
          id,
          CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) as full_name,
          CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email,
          avatar_url,
          email_verified,
          facebook_id,
          two_factor_enabled
         FROM users 
         WHERE id = ?`,
        [userIdBinary]
      );
      user = userDetails[0];
    } else {
      // Check if email is already registered (regular auth)
      const [existingUserByEmail] = await pool.execute(
        `SELECT id FROM users WHERE CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) = ?`,
        [email]
      );

      if (existingUserByEmail.length > 0) {
        // Email exists with regular auth - Link Facebook account
        userIdBinary = existingUserByEmail[0].id;
        isNewUser = false; // This is an existing user, not a new registration
        
        await pool.execute(
          'UPDATE users SET facebook_id = ?, avatar_url = ?, last_login_attempt = ?, email_verified = 1 WHERE id = ?',
          [facebookId, photoUrl, now, userIdBinary]
        );

        // Get updated user details including 2FA status
        const [userDetails] = await pool.execute(
          `SELECT 
            id,
            CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) as full_name,
            CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email,
            avatar_url,
            email_verified,
            facebook_id,
            two_factor_enabled
           FROM users 
           WHERE id = ?`,
          [userIdBinary]
        );
        user = userDetails[0];
      } else {
        // New user - REGISTRATION
        isNewUser = true;
        
        // Generate a random password (user won't use it, but DB might require it)
        const randomPassword = await bcrypt.hash(
          Math.random().toString(36).slice(-16),
          12
        );

        // Generate UUID for new user
        const userId = generateUUID();
        userIdBinary = uuidToBinary(userId);

        // Insert new user with Facebook credentials
        await pool.execute(
          `INSERT INTO users 
           (id, full_name, email, password_hash, facebook_id, avatar_url, email_verified, created_at) 
           VALUES (?, AES_ENCRYPT(?, ${encryptionKey}), AES_ENCRYPT(?, ${encryptionKey}), ?, ?, ?, TRUE, NOW())`,
          [userIdBinary, fullName, email, randomPassword, facebookId, photoUrl]
        );

        // Get the newly created user including 2FA status
        const [newUserDetails] = await pool.execute(
          `SELECT 
            id,
            CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) as full_name,
            CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email,
            avatar_url,
            email_verified,
            facebook_id,
            two_factor_enabled
           FROM users 
           WHERE id = ?`,
          [userIdBinary]
        );
        user = newUserDetails[0];
      }
    }

    // Convert binary UUID to string
    const userUuid = binaryToUuid(user.id);

    // Debug logging for 2FA check
    console.log('🔐 Facebook Auth - 2FA Check:');
    console.log('  User ID:', userUuid);
    console.log('  Email:', user.email);
    console.log('  two_factor_enabled:', user.two_factor_enabled, '(type:', typeof user.two_factor_enabled, ')');
    console.log('  isNewUser:', isNewUser);
    console.log('  Condition (user.two_factor_enabled && !isNewUser):', user.two_factor_enabled && !isNewUser);

    // Check if 2FA is enabled
    if (user.two_factor_enabled && !isNewUser) {
      console.log('✅ 2FA required - returning requires2FA response');
      // Don't generate full token yet, return partial response requiring 2FA
      return res.json({
        message: '2FA verification required',
        requires2FA: true,
        userId: userUuid,
        user: formatUserResponse(user)
      });
    }

    console.log('⚠️ 2FA not required - proceeding with token generation');

    // Generate JWT token (only if 2FA is not enabled or new user)
    const token = jwt.sign(
      {
        userId: userUuid,
        email: user.email,
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    // Return success response
    return res.status(isNewUser ? 201 : 200).json({
      message: isNewUser 
        ? 'Account created successfully with Facebook' 
        : 'Logged in successfully with Facebook',
      token: token,
      user: formatUserResponse(user)
    });

  } catch (error) {
    console.error('Facebook auth error:', error);
    return res.status(500).json({
      message: 'Internal server error during Facebook authentication'
    });
  }
});

// Google authentication endpoint (handles both login and registration)
app.post('/api/auth/google', async (req, res) => {
  try {
    const { email, fullName, googleId, photoUrl } = req.body;

    // Validate required fields
    if (!email || !fullName || !googleId) {
      return res.status(400).json({
        message: 'Email, full name, and Google ID are required'
      });
    }

    const encryptionKey = getEncryptionKeyQuery();
    const now = new Date();

    // Check if user already exists with this googleId
    const [existingUserByGoogleId] = await pool.execute(
      'SELECT id FROM users WHERE google_id = ?',
      [googleId]
    );

    let user;
    let isNewUser = false;
    let userIdBinary;

    if (existingUserByGoogleId.length > 0) {
      // User exists with Google ID - LOGIN
      userIdBinary = existingUserByGoogleId[0].id;
      
      // Update last login timestamp
      await pool.execute(
        'UPDATE users SET last_login_attempt = ? WHERE id = ?',
        [now, userIdBinary]
      );

      // Get full user details including 2FA status
      const [userDetails] = await pool.execute(
        `SELECT 
          id,
          CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) as full_name,
          CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email,
          avatar_url,
          email_verified,
          google_id,
          two_factor_enabled
         FROM users 
         WHERE id = ?`,
        [userIdBinary]
      );
      user = userDetails[0];
    } else {
      // Check if email is already registered (regular auth)
      const [existingUserByEmail] = await pool.execute(
        `SELECT id FROM users WHERE CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) = ?`,
        [email]
      );

      if (existingUserByEmail.length > 0) {
        // Email exists with regular auth - Link Google account
        userIdBinary = existingUserByEmail[0].id;
        isNewUser = false; // This is an existing user, not a new registration
        
        await pool.execute(
          'UPDATE users SET google_id = ?, avatar_url = ?, last_login_attempt = ?, email_verified = 1 WHERE id = ?',
          [googleId, photoUrl, now, userIdBinary]
        );

        // Get updated user details including 2FA status
        const [userDetails] = await pool.execute(
          `SELECT 
            id,
            CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) as full_name,
            CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email,
            avatar_url,
            email_verified,
            google_id,
            two_factor_enabled
           FROM users 
           WHERE id = ?`,
          [userIdBinary]
        );
        user = userDetails[0];
      } else {
        // New user - REGISTRATION
        isNewUser = true;
        
        // Generate a random password (user won't use it, but DB might require it)
        const randomPassword = await bcrypt.hash(
          Math.random().toString(36).slice(-16),
          12
        );

        // Generate UUID for new user
        const userId = generateUUID();
        userIdBinary = uuidToBinary(userId);

        // Insert new user with Google credentials
        await pool.execute(
          `INSERT INTO users 
           (id, full_name, email, password_hash, google_id, avatar_url, email_verified, created_at) 
           VALUES (?, AES_ENCRYPT(?, ${encryptionKey}), AES_ENCRYPT(?, ${encryptionKey}), ?, ?, ?, TRUE, NOW())`,
          [userIdBinary, fullName, email, randomPassword, googleId, photoUrl]
        );

        // Get the newly created user including 2FA status
        const [newUserDetails] = await pool.execute(
          `SELECT 
            id,
            CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) as full_name,
            CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email,
            avatar_url,
            email_verified,
            google_id,
            two_factor_enabled
           FROM users 
           WHERE id = ?`,
          [userIdBinary]
        );
        user = newUserDetails[0];
      }
    }

    // Convert binary UUID to string
    const userUuid = binaryToUuid(user.id);

    // Debug logging for 2FA check
    console.log('🔐 Google Auth - 2FA Check:');
    console.log('  User ID:', userUuid);
    console.log('  Email:', user.email);
    console.log('  two_factor_enabled:', user.two_factor_enabled, '(type:', typeof user.two_factor_enabled, ')');
    console.log('  isNewUser:', isNewUser);
    console.log('  Condition (user.two_factor_enabled && !isNewUser):', user.two_factor_enabled && !isNewUser);

    // Check if 2FA is enabled
    if (user.two_factor_enabled && !isNewUser) {
      console.log('✅ 2FA required - returning requires2FA response');
      // Don't generate full token yet, return partial response requiring 2FA
      return res.json({
        message: '2FA verification required',
        requires2FA: true,
        userId: userUuid,
        user: formatUserResponse(user)
      });
    }

    console.log('⚠️ 2FA not required - proceeding with token generation');

    // Generate JWT token (only if 2FA is not enabled or new user)
    const token = jwt.sign(
      {
        userId: userUuid,
        email: user.email,
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    // Return success response
    return res.status(isNewUser ? 201 : 200).json({
      message: isNewUser 
        ? 'Account created successfully with Google' 
        : 'Logged in successfully with Google',
      token: token,
      user: formatUserResponse(user)
    });

  } catch (error) {
    console.error('Google auth error:', error);
    return res.status(500).json({
      message: 'Internal server error during Google authentication'
    });
  }
});

// ==========================================
// User profile endpoints (auth required)
// ==========================================
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (req.user.userId !== id) return res.status(403).json({ message: 'Forbidden' });
    const encryptionKey = getEncryptionKeyQuery();
    const [rows] = await pool.execute(
      `SELECT id,
              CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) AS full_name,
              CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) AS email,
              avatar_url,
              email_verified,
              two_factor_enabled,
              google_id,
              facebook_id,
              created_at, updated_at, name_changed_at
       FROM users WHERE id = ?`,
      [uuidToBinary(id)]
    );
    if (rows.length === 0) return res.status(404).json({ message: 'User not found' });
    const u = rows[0];
    const isSocialLogin = !!(u.google_id || u.facebook_id);
    res.json({
      id: binaryToUuid(u.id),
      fullName: u.full_name,
      email: u.email,
      avatarUrl: u.avatar_url || null,
      emailVerified: u.email_verified || false,
      twoFactorEnabled: u.two_factor_enabled || false,
      isSocialLogin: isSocialLogin,
      googleId: u.google_id || null,
      facebookId: u.facebook_id || null,
      createdAt: u.created_at,
      updatedAt: u.updated_at,
      nameChangedAt: u.name_changed_at || null,
    });
  } catch (e) {
    console.error('Get user error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (req.user.userId !== id) return res.status(403).json({ message: 'Forbidden' });
    const { fullName, email, avatarUrl } = req.body || {};
    const encryptionKey = getEncryptionKeyQuery();
    const fields = [];
    const values = [];
    
    // Check if name is being changed and enforce cooldown
    if (fullName) {
      // Get current user data to check last name change
      const [rows] = await pool.execute(
        `SELECT name_changed_at FROM users WHERE id = ?`,
        [uuidToBinary(id)]
      );
      
      if (rows.length > 0 && rows[0].name_changed_at) {
        const lastChange = new Date(rows[0].name_changed_at);
        const daysSinceChange = Math.floor((Date.now() - lastChange.getTime()) / (1000 * 60 * 60 * 24));
        
        if (daysSinceChange < 7) {
          const daysRemaining = 7 - daysSinceChange;
          return res.status(400).json({ 
            message: `You can change your name again in ${daysRemaining} day(s). Name changes are limited to once per week.`,
            daysRemaining 
          });
        }
      }
      
      fields.push(`full_name = AES_ENCRYPT(?, ${encryptionKey})`);
      fields.push('name_changed_at = NOW()');
      values.push(fullName);
    }
    
    if (email) {
      fields.push(`email = AES_ENCRYPT(?, ${encryptionKey})`);
      values.push(email);
    }
    if (avatarUrl !== undefined) {
      fields.push('avatar_url = ?');
      values.push(avatarUrl);
    }
    if (fields.length === 0) return res.status(400).json({ message: 'No fields to update' });
    values.push(uuidToBinary(id));
    await pool.execute(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, values);
    res.json({ success: true });
  } catch (e) {
    console.error('Update user error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Upload avatar image to Cloudinary and save URL
app.post('/api/users/:id/avatar', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { id } = req.params;
    if (req.user.userId !== id) return res.status(403).json({ message: 'Forbidden' });

    // Allow setting a remote URL directly (e.g., DiceBear) without upload
    if (!req.file && req.body && req.body.url) {
      const url = req.body.url;
      await pool.execute('UPDATE users SET avatar_url = ? WHERE id = ?', [url, uuidToBinary(id)]);
      return res.json({ avatarUrl: url });
    }

    if (!req.file) return res.status(400).json({ message: 'No image provided' });

    if (!cloudinary.config().cloud_name) {
      return res.status(500).json({ message: 'Cloudinary is not configured' });
    }

    const bufferStream = new stream.PassThrough();
    bufferStream.end(req.file.buffer);
    const uploaded = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        { folder: 'para/avatars', resource_type: 'image' },
        (error, result) => {
          if (error) return reject(error);
          resolve(result);
        }
      );
      bufferStream.pipe(uploadStream);
    });

    const secureUrl = uploaded.secure_url;
    await pool.execute('UPDATE users SET avatar_url = ? WHERE id = ?', [secureUrl, uuidToBinary(id)]);
    res.json({ avatarUrl: secureUrl });
  } catch (e) {
    console.error('Avatar upload error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// =============================
// Support & Feedback Endpoints
// =============================

// Submit a support report (bug, performance issue, etc.)
app.post('/api/support/reports', authenticateToken, async (req, res) => {
  try {
    const { userId, category, description } = req.body || {};

    if (!userId || !category || !description) {
      return res.status(400).json({ message: 'userId, category, and description are required' });
    }

    if (!req.user || req.user.userId !== userId) {
      return res.status(403).json({ message: 'Forbidden: userId does not match authenticated user' });
    }

    const userIdBinary = uuidToBinary(userId);

    const [result] = await pool.execute(
      'INSERT INTO support_reports (user_id, category, description, status, created_at) VALUES (?, ?, ?, ?, NOW())',
      [userIdBinary, category, description, 'open']
    );

    res.status(201).json({
      success: true,
      message: 'Report submitted successfully',
      reportId: result.insertId,
    });
  } catch (error) {
    console.error('Error submitting support report:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Submit general user feedback
app.post('/api/support/feedback', authenticateToken, async (req, res) => {
  try {
    const { userId, feedback } = req.body || {};

    if (!userId || !feedback) {
      return res.status(400).json({ message: 'userId and feedback are required' });
    }

    if (!req.user || req.user.userId !== userId) {
      return res.status(403).json({ message: 'Forbidden: userId does not match authenticated user' });
    }

    const userIdBinary = uuidToBinary(userId);

    const [result] = await pool.execute(
      'INSERT INTO support_feedback (user_id, feedback, created_at) VALUES (?, ?, NOW())',
      [userIdBinary, feedback]
    );

    res.status(201).json({
      success: true,
      message: 'Feedback submitted successfully',
      feedbackId: result.insertId,
    });
  } catch (error) {
    console.error('Error submitting feedback:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============================================================================
// Chat endpoints - support both /api/chats/:userId/messages format and 
// /api/chats/messages with JWT auth for backward compatibility
// ============================================================================

// Get messages for a user by userId (with optional JWT verification)
app.get('/api/chats/:userId/messages', optionalAuthenticateToken, async (req, res) => {
  try {
    const userIdParam = req.params.userId;
    console.log(`[GET /api/chats/:userId/messages] Request received for userId: ${userIdParam}`);
    
    // Validate UUID format (basic check)
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(userIdParam)) {
      console.error(`[GET] Invalid user ID format (not a UUID): ${userIdParam}`);
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    console.log(`[GET] Parsed userId: ${userIdParam}, Authenticated user: ${req.user ? req.user.userId : 'none'}`);

    // If JWT token is provided, verify userId matches authenticated user
    if (req.user && req.user.userId !== userIdParam) {
      console.error(`[GET] User ID mismatch. Token userId: ${req.user.userId}, Request userId: ${userIdParam}`);
      return res.status(403).json({ message: 'Access denied: User ID mismatch' });
    }

    // Convert UUID string to binary for database query
    const userIdBinary = uuidToBinary(userIdParam);

    // Verify user exists
    const [userCheck] = await pool.execute(
      'SELECT id FROM users WHERE id = ?',
      [userIdBinary]
    );
    if (userCheck.length === 0) {
      console.error(`[GET] User not found in database: ${userIdParam}`);
      return res.status(404).json({ message: 'User not found' });
    }

    const [rows] = await pool.execute(
      `SELECT id, user_id, text, is_bot as isBot, timestamp, error 
       FROM messages 
       WHERE user_id = ?
       ORDER BY timestamp ASC`,
      [userIdBinary]
    );

    console.log(`[GET] Found ${rows.length} messages for user ${userIdParam}`);

    // Format response to match Flutter expectations
    const formattedRows = rows.map(row => ({
      id: row.id,
      userId: binaryToUuid(row.user_id) || userIdParam, // Convert binary UUID to string
      text: row.text,
      isBot: row.isBot === 1 || row.isBot === true,
      timestamp: row.timestamp ? new Date(row.timestamp).toISOString() : new Date().toISOString(),
      error: row.error
    }));

    res.json(formattedRows);
  } catch (error) {
    console.error('[GET] Error fetching messages:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Post a new message for a user (with optional JWT verification)
app.post('/api/chats/:userId/messages', optionalAuthenticateToken, async (req, res) => {
  try {
    const userIdParam = req.params.userId;
    console.log(`[POST /api/chats/:userId/messages] Request received for userId: ${userIdParam}`);
    console.log(`[POST] Request body:`, JSON.stringify(req.body));
    
    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(userIdParam)) {
      console.error(`[POST] Invalid user ID format (not a UUID): ${userIdParam}`);
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    console.log(`[POST] Parsed userId: ${userIdParam}, Authenticated user: ${req.user ? req.user.userId : 'none'}`);

    // If JWT token is provided, verify userId matches authenticated user
    if (req.user && req.user.userId !== userIdParam) {
      console.error(`[POST] User ID mismatch. Token userId: ${req.user.userId}, Request userId: ${userIdParam}`);
      return res.status(403).json({ message: 'Access denied: User ID mismatch' });
    }

    // Convert UUID string to binary for database query
    const userIdBinary = uuidToBinary(userIdParam);

    // Verify user exists
    const [userCheck] = await pool.execute(
      'SELECT id FROM users WHERE id = ?',
      [userIdBinary]
    );
    if (userCheck.length === 0) {
      console.error(`[POST] User not found in database: ${userIdParam}`);
      return res.status(404).json({ message: 'User not found' });
    }

    const { text, isBot, timestamp, error } = req.body;
    const messageTimestamp = timestamp ? new Date(timestamp) : new Date();
    
    console.log(`[POST] Inserting message for user ${userIdParam}: text="${text?.substring(0, 50)}...", isBot=${isBot}`);
    
    const [result] = await pool.execute(
      'INSERT INTO messages (user_id, text, is_bot, timestamp, error) VALUES (?, ?, ?, ?, ?)',
      [userIdBinary, text, isBot ? 1 : 0, messageTimestamp, error || null]
    );

    console.log(`[POST] Message saved successfully with ID: ${result.insertId}`);

    res.status(201).json({
      id: result.insertId,
      userId: userIdParam,
      text,
      isBot: isBot ? true : false,
      timestamp: messageTimestamp.toISOString(),
      error: error || null
    });
  } catch (error) {
    console.error('[POST] Error saving message:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delete all messages for a user (with optional JWT verification)
app.delete('/api/chats/:userId/messages', optionalAuthenticateToken, async (req, res) => {
  try {
    const userIdParam = req.params.userId;
    
    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(userIdParam)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    // If JWT token is provided, verify userId matches authenticated user
    if (req.user && req.user.userId !== userIdParam) {
      return res.status(403).json({ message: 'Access denied: User ID mismatch' });
    }

    // Convert UUID string to binary for database query
    const userIdBinary = uuidToBinary(userIdParam);

    // Verify user exists
    const [userCheck] = await pool.execute(
      'SELECT id FROM users WHERE id = ?',
      [userIdBinary]
    );
    if (userCheck.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    await pool.execute('DELETE FROM messages WHERE user_id = ?', [userIdBinary]);
    res.status(200).json({ success: true, message: 'All messages deleted successfully' });
  } catch (error) {
    console.error('Error deleting messages:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Backward compatibility: Get messages for authenticated user (JWT required)
app.get('/api/chats/messages', authenticateToken, async (req, res) => {
  try {
    const userIdBinary = uuidToBinary(req.user.userId);
    const [rows] = await pool.execute(
      `SELECT id, user_id, text, is_bot as isBot, timestamp, error 
       FROM messages 
       WHERE user_id = ?
       ORDER BY timestamp ASC`,
      [userIdBinary]
    );

    const formattedRows = rows.map(row => ({
      id: row.id,
      userId: binaryToUuid(row.user_id) || req.user.userId,
      text: row.text,
      isBot: row.isBot === 1 || row.isBot === true,
      timestamp: row.timestamp ? new Date(row.timestamp).toISOString() : new Date().toISOString(),
      error: row.error
    }));

    res.json(formattedRows);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Backward compatibility: Post a new message (JWT required)
app.post('/api/chats/messages', authenticateToken, async (req, res) => {
  try {
    const { text, isBot, timestamp, error } = req.body;
    const messageTimestamp = timestamp ? new Date(timestamp) : new Date();
    const userIdBinary = uuidToBinary(req.user.userId);
    
    const [result] = await pool.execute(
      'INSERT INTO messages (user_id, text, is_bot, timestamp, error) VALUES (?, ?, ?, ?, ?)',
      [userIdBinary, text, isBot ? 1 : 0, messageTimestamp, error || null]
    );

    res.status(201).json({
      id: result.insertId,
      userId: req.user.userId,
      text,
      isBot: isBot ? true : false,
      timestamp: messageTimestamp.toISOString(),
      error: error || null
    });
  } catch (error) {
    console.error('Error saving message:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Backward compatibility: Delete all messages (JWT required)
app.delete('/api/chats/messages', authenticateToken, async (req, res) => {
  try {
    const userIdBinary = uuidToBinary(req.user.userId);
    await pool.execute('DELETE FROM messages WHERE user_id = ?', [userIdBinary]);
    res.json({ success: true, message: 'All messages deleted successfully' });
  } catch (error) {
    console.error('Error deleting messages:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// =============================
// Email Verification Endpoints
// =============================

// Send verification email
app.post('/api/users/:id/send-verification', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Ensure user can only request verification for their own account
    if (req.user.userId !== id) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    const encryptionKey = getEncryptionKeyQuery();
    const userIdBinary = uuidToBinary(id);

    // Get user details
    const [users] = await pool.execute(
      `SELECT 
        CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) as full_name,
        CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email,
        email_verified
       FROM users 
       WHERE id = ?`,
      [userIdBinary]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = users[0];

    // Check if already verified
    if (user.email_verified) {
      return res.status(400).json({ message: 'Email already verified' });
    }

    // Generate verification token (valid for 24 hours)
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now

    // Save token to database
    await pool.execute(
      'UPDATE users SET verification_token = ?, verification_token_expires = ? WHERE id = ?',
      [verificationToken, tokenExpiry, userIdBinary]
    );

    // Send verification email
    const emailSent = await sendVerificationEmail(user.email, user.full_name, verificationToken);

    if (emailSent) {
      res.json({ 
        success: true, 
        message: 'Verification email sent successfully' 
      });
    } else {
      res.status(500).json({ 
        message: 'Failed to send verification email. Please try again later.' 
      });
    }
  } catch (error) {
    console.error('Error sending verification email:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify email with token
app.get('/api/auth/verify-email/:token', async (req, res) => {
  try {
    const { token } = req.params;

    // Find user with this token
    const [users] = await pool.execute(
      'SELECT id, email_verified, verification_token_expires FROM users WHERE verification_token = ?',
      [token]
    );

    if (users.length === 0) {
      const { redirect } = req.query;
      if (redirect) {
        return res.status(400).send(`
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verification Failed - Para App</title>
            <style>
              body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); color: white; margin: 0; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; }
              .container { background: rgba(255,255,255,0.1); padding: 40px; border-radius: 20px; backdrop-filter: blur(10px); max-width: 500px; }
              .icon { font-size: 64px; margin-bottom: 20px; }
              h1 { margin-bottom: 20px; font-size: 32px; }
              p { margin-bottom: 30px; font-size: 18px; opacity: 0.9; }
              .button { display: inline-block; padding: 15px 30px; background: white; color: #ff6b6b; text-decoration: none; border-radius: 10px; font-weight: 600; font-size: 16px; margin: 10px; transition: all 0.3s ease; }
              .button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0,0,0,0.2); }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="icon">❌</div>
              <h1>Invalid Verification Link</h1>
              <p>This verification link is invalid or has already been used.</p>
              <a href="${redirect}" class="button">Return to Para App</a>
            </div>
          </body>
          </html>
        `);
      }
      return res.status(400).json({ message: 'Invalid verification token' });
    }

    const user = users[0];

    // Check if already verified
    if (user.email_verified) {
      const { redirect } = req.query;
      if (redirect) {
        return res.status(400).send(`
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Already Verified - Para App</title>
            <style>
              body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #ffa502 0%, #ff6348 100%); color: white; margin: 0; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; }
              .container { background: rgba(255,255,255,0.1); padding: 40px; border-radius: 20px; backdrop-filter: blur(10px); max-width: 500px; }
              .icon { font-size: 64px; margin-bottom: 20px; }
              h1 { margin-bottom: 20px; font-size: 32px; }
              p { margin-bottom: 30px; font-size: 18px; opacity: 0.9; }
              .button { display: inline-block; padding: 15px 30px; background: white; color: #ffa502; text-decoration: none; border-radius: 10px; font-weight: 600; font-size: 16px; margin: 10px; transition: all 0.3s ease; }
              .button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0,0,0,0.2); }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="icon">✅</div>
              <h1>Email Already Verified</h1>
              <p>Your email is already verified. You can continue using the Para app.</p>
              <a href="${redirect}" class="button">Return to Para App</a>
            </div>
          </body>
          </html>
        `);
      }
      return res.status(400).json({ message: 'Email already verified' });
    }

    // Check if token expired
    const now = new Date();
    const expiryDate = new Date(user.verification_token_expires);
    
    if (now > expiryDate) {
      const { redirect } = req.query;
      if (redirect) {
        return res.status(400).send(`
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Link Expired - Para App</title>
            <style>
              body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #ff7675 0%, #d63031 100%); color: white; margin: 0; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; }
              .container { background: rgba(255,255,255,0.1); padding: 40px; border-radius: 20px; backdrop-filter: blur(10px); max-width: 500px; }
              .icon { font-size: 64px; margin-bottom: 20px; }
              h1 { margin-bottom: 20px; font-size: 32px; }
              p { margin-bottom: 30px; font-size: 18px; opacity: 0.9; }
              .button { display: inline-block; padding: 15px 30px; background: white; color: #ff7675; text-decoration: none; border-radius: 10px; font-weight: 600; font-size: 16px; margin: 10px; transition: all 0.3s ease; }
              .button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0,0,0,0.2); }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="icon">⏰</div>
              <h1>Link Expired</h1>
              <p>This verification link has expired. Please request a new verification email from the app.</p>
              <a href="${redirect}" class="button">Return to Para App</a>
            </div>
          </body>
          </html>
        `);
      }
      return res.status(400).json({ message: 'Verification token has expired. Please request a new one.' });
    }

    // Mark email as verified and clear token
    await pool.execute(
      'UPDATE users SET email_verified = 1, verification_token = NULL, verification_token_expires = NULL WHERE id = ?',
      [user.id]
    );

    // Check if redirect parameter exists (for mobile app deep link)
    const { redirect } = req.query;
    
    if (redirect) {
      // Return HTML page that redirects to mobile app
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Email Verified - Para App</title>
          <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; margin: 0; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; }
            .container { background: rgba(255,255,255,0.1); padding: 40px; border-radius: 20px; backdrop-filter: blur(10px); max-width: 500px; }
            .icon { font-size: 64px; margin-bottom: 20px; }
            h1 { margin-bottom: 20px; font-size: 32px; }
            p { margin-bottom: 30px; font-size: 18px; opacity: 0.9; }
            .button { display: inline-block; padding: 15px 30px; background: white; color: #667eea; text-decoration: none; border-radius: 10px; font-weight: 600; font-size: 16px; margin: 10px; transition: all 0.3s ease; }
            .button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0,0,0,0.2); }
            .countdown { margin-top: 20px; font-size: 14px; opacity: 0.8; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="icon">✅</div>
            <h1>Email Verified Successfully!</h1>
            <p>Your email has been verified. You can now return to the Para app.</p>
            <a href="${redirect}" class="button">Open Para App</a>
            <div class="countdown" id="countdown">Redirecting in 5 seconds...</div>
          </div>
          <script>
            let countdown = 5;
            const countdownEl = document.getElementById('countdown');
            
            const timer = setInterval(() => {
              countdown--;
              countdownEl.textContent = \`Redirecting in \${countdown} seconds...\`;
              
              if (countdown <= 0) {
                clearInterval(timer);
                window.location.href = '${redirect}';
              }
            }, 1000);
            
            // Also redirect immediately if user clicks the button
            document.querySelector('.button').addEventListener('click', (e) => {
              e.preventDefault();
              clearInterval(timer);
              window.location.href = '${redirect}';
            });
          </script>
        </body>
        </html>
      `);
    } else {
      // Return JSON for API calls
      res.json({ 
        success: true, 
        message: 'Email verified successfully!' 
      });
    }
  } catch (error) {
    console.error('Error verifying email:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// =============================
// Password Reset Endpoints
// =============================

// Function to send password reset email
async function sendPasswordResetEmail(email, fullName, resetToken) {
  // Use deep link for mobile app: paraapp://reset-password?token=xxx
  // Falls back to web URL if FRONTEND_URL is set
  const resetUrl = `${process.env.FRONTEND_URL || 'paraapp://reset-password'}?token=${resetToken}`;
  
  // Try SendGrid API first if configured, fallback to SMTP
  if (process.env.EMAIL_HOST === 'smtp.sendgrid.net' && process.env.EMAIL_USER === 'apikey') {
    return await sendPasswordResetEmailViaSendGridAPI(email, fullName, resetToken);
  }
  
  const mailOptions = {
    from: `"${process.env.EMAIL_FROM_NAME || 'Para App'}" <${process.env.EMAIL_FROM_ADDRESS || process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Reset Your Password - Para App',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f4f4f4; margin: 0; padding: 0; }
          .container { max-width: 600px; margin: 20px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 20px; text-align: center; }
          .header h1 { color: white; margin: 0; font-size: 28px; }
          .content { padding: 40px 30px; }
          .content h2 { color: #333; margin-top: 0; }
          .content p { color: #666; margin: 15px 0; }
          .button { display: inline-block; padding: 14px 32px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 8px; font-weight: 600; margin: 20px 0; }
          .button:hover { opacity: 0.9; }
          .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #999; font-size: 12px; }
          .token-box { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0; font-family: monospace; word-break: break-all; }
          .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin: 20px 0; color: #856404; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 Reset Your Password</h1>
          </div>
          <div class="content">
            <h2>Hi ${fullName},</h2>
            <p>We received a request to reset your password for your Para account.</p>
            <p>Click the button below to create a new password:</p>
            <div style="text-align: center;">
              <a href="${resetUrl}" class="button">Reset Password</a>
            </div>
            <p style="margin-top: 30px;">Or copy and paste this link into your browser:</p>
            <div class="token-box">${resetUrl}</div>
            <p><strong>This link will expire in 1 hour.</strong></p>
            <div class="warning">
              <strong>⚠️ Security Note:</strong> If you didn't request this password reset, please ignore this email. Your password will remain unchanged.
            </div>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} Para App. All rights reserved.</p>
            <p>This is an automated email. Please do not reply.</p>
          </div>
        </div>
      </body>
      </html>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`✅ Password reset email sent to ${email}`);
    return true;
  } catch (error) {
    console.error('❌ Error sending password reset email:', error);
    return false;
  }
}

// SendGrid API fallback for password reset
async function sendPasswordResetEmailViaSendGridAPI(email, fullName, resetToken) {
  const sgMail = require('@sendgrid/mail');
  sgMail.setApiKey(process.env.EMAIL_PASSWORD);
  
  const resetUrl = `https://para-backend-eukj.onrender.com/api/auth/reset-password/${resetToken}?redirect=paraapp://reset-password`;
  
  const msg = {
    to: email,
    from: {
      email: process.env.EMAIL_FROM_ADDRESS || 'support-app.online',
      name: process.env.EMAIL_FROM_NAME || 'Para App'
    },
    subject: 'Reset Your Password - Para App',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f4f4f4; margin: 0; padding: 0; }
          .container { max-width: 600px; margin: 20px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 20px; text-align: center; }
          .header h1 { color: white; margin: 0; font-size: 28px; }
          .content { padding: 40px 30px; }
          .content h2 { color: #333; margin-top: 0; }
          .content p { color: #666; margin: 15px 0; }
          .button { display: inline-block; padding: 14px 32px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 8px; font-weight: 600; margin: 20px 0; }
          .button:hover { opacity: 0.9; }
          .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #999; font-size: 12px; }
          .token-box { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0; font-family: monospace; word-break: break-all; }
          .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin: 20px 0; color: #856404; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 Reset Your Password</h1>
          </div>
          <div class="content">
            <h2>Hi ${fullName},</h2>
            <p>We received a request to reset your password for your Para account.</p>
            <p>Click the button below to create a new password:</p>
            <div style="text-align: center;">
              <a href="${resetUrl}" class="button">Reset Password</a>
            </div>
            <p style="margin-top: 30px;">Or copy and paste this link into your browser:</p>
            <div class="token-box">${resetUrl}</div>
            <p><strong>This link will expire in 1 hour.</strong></p>
            <div class="warning">
              <strong>⚠️ Security Note:</strong> If you didn't request this password reset, please ignore this email. Your password will remain unchanged.
            </div>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} Para App. All rights reserved.</p>
            <p>This is an automated email. Please do not reply.</p>
          </div>
        </div>
      </body>
      </html>
    `,
  };

  try {
    await sgMail.send(msg);
    console.log(`✅ Password reset email sent via SendGrid API to ${email}`);
    return true;
  } catch (error) {
    console.error('❌ Error sending via SendGrid API:', error.response?.body || error);
    return false;
  }
}

// Request password reset
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    const encryptionKey = getEncryptionKeyQuery();

    // Find user with this email
    const [users] = await pool.execute(
      `SELECT 
        id,
        CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) as full_name,
        CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email
       FROM users 
       WHERE CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) = ?`,
      [email]
    );

    // Always return success message for security (don't reveal if email exists)
    if (users.length === 0) {
      return res.json({ 
        success: true, 
        message: 'If an account exists for this email, you will receive reset instructions.' 
      });
    }

    const user = users[0];

    // Generate reset token (valid for 1 hour)
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour from now

    // Save token to database
    await pool.execute(
      'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?',
      [resetToken, tokenExpiry, user.id]
    );

    // Send password reset email
    const emailSent = await sendPasswordResetEmail(user.email, user.full_name, resetToken);

    if (emailSent) {
      res.json({ 
        success: true, 
        message: 'If an account exists for this email, you will receive reset instructions.' 
      });
    } else {
      res.status(500).json({ 
        message: 'Failed to send password reset email. Please try again later.' 
      });
    }
  } catch (error) {
    console.error('Error requesting password reset:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify reset token (optional, for checking validity before showing reset form)
app.get('/api/auth/verify-reset-token/:token', async (req, res) => {
  try {
    const { token } = req.params;

    // Find user with this token
    const [users] = await pool.execute(
      'SELECT id, reset_token_expires FROM users WHERE reset_token = ?',
      [token]
    );

    if (users.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired reset token' 
      });
    }

    const user = users[0];

    // Check if token expired
    const now = new Date();
    const expiryDate = new Date(user.reset_token_expires);
    
    if (now > expiryDate) {
      return res.status(400).json({ 
        success: false, 
        message: 'Reset token has expired. Please request a new one.' 
      });
    }

    res.json({ 
      success: true, 
      message: 'Token is valid' 
    });
  } catch (error) {
    console.error('Error verifying reset token:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Handle password reset link from email (HTML/deep link redirect)
app.get('/api/auth/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const redirectBase = req.query.redirect;

    const [users] = await pool.execute(
      'SELECT id, reset_token_expires FROM users WHERE reset_token = ?',
      [token]
    );

    if (users.length === 0) {
      return res.status(400).send(buildResetHtml({
        title: 'Invalid Reset Link',
        emoji: '❌',
        message:
          'This password reset link is invalid or has already been used. Please request a new link from the Para app.',
        buttonLabel: 'Back to Para App',
        buttonHref: redirectBase || process.env.FRONTEND_URL || 'https://para-app.online',
      }));
    }

    const user = users[0];
    const now = new Date();
    const expiryDate = new Date(user.reset_token_expires);

    if (now > expiryDate) {
      return res.status(400).send(buildResetHtml({
        title: 'Reset Link Expired',
        emoji: '⏰',
        message:
          'This password reset link has expired. Please request a new link from the Para app.',
        buttonLabel: 'Request New Link',
        buttonHref: redirectBase || process.env.FRONTEND_URL || 'https://para-app.online',
      }));
    }

    const redirectTarget = (() => {
      if (!redirectBase) return null;
      const connector = redirectBase.includes('?') ? '&' : '?';
      return `${redirectBase}${connector}token=${token}`;
    })();

    if (redirectTarget) {
      return res.send(buildResetHtml({
        title: 'Open Para App to Reset Password',
        emoji: '🔐',
        message:
          'Tap the button below to continue resetting your password in the Para app.',
        buttonLabel: 'Open Para App',
        buttonHref: redirectTarget,
        redirectHref: redirectTarget,
      }));
    }

    // No redirect specified: return JSON for browser clients
    res.json({
      success: true,
      message: 'Reset token is valid. Submit POST /api/auth/reset-password with your new password.',
      token,
    });
  } catch (error) {
    console.error('Error handling reset password link:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Reset password with token
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ message: 'Token and new password are required' });
    }

    // Validate password strength (minimum 6 characters)
    if (newPassword.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long' });
    }

    // Find user with this token
    const [users] = await pool.execute(
      'SELECT id, reset_token_expires FROM users WHERE reset_token = ?',
      [token]
    );

    if (users.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    const user = users[0];

    // Check if token expired
    const now = new Date();
    const expiryDate = new Date(user.reset_token_expires);
    
    if (now > expiryDate) {
      return res.status(400).json({ 
        message: 'Reset token has expired. Please request a new one.' 
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update password and clear reset token
    await pool.execute(
      'UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
      [hashedPassword, user.id]
    );

    res.json({ 
      success: true, 
      message: 'Password reset successfully!' 
    });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Change password endpoint (requires authentication and current password)
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { userId, currentPassword, newPassword } = req.body;

    // Validate input
    if (!userId || !currentPassword || !newPassword) {
      return res.status(400).json({ 
        success: false,
        message: 'User ID, current password, and new password are required' 
      });
    }

    // Validate new password strength (minimum 8 characters)
    if (newPassword.length < 8) {
      return res.status(400).json({ 
        success: false,
        message: 'New password must be at least 8 characters long' 
      });
    }

    // Validate new password complexity
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).+$/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({ 
        success: false,
        message: 'Password must include uppercase, number, and special character' 
      });
    }

    // Check if new password is same as current
    if (currentPassword === newPassword) {
      return res.status(400).json({ 
        success: false,
        message: 'New password must be different from current password' 
      });
    }

    // Convert userId to binary
    const userIdBinary = uuidToBinary(userId);

    // Get user's current password hash
    const [users] = await pool.execute(
      'SELECT id, password_hash FROM users WHERE id = ?',
      [userIdBinary]
    );

    if (users.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    const user = users[0];

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
    
    if (!isMatch) {
      return res.status(400).json({ 
        success: false,
        message: 'Current password is incorrect' 
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update password and store old password hash with timestamp
    await pool.execute(
      'UPDATE users SET password_hash = ?, old_password_hash = ?, password_changed_at = NOW() WHERE id = ?',
      [hashedPassword, user.password_hash, userIdBinary]
    );

    res.json({ 
      success: true, 
      message: 'Password changed successfully!' 
    });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// Verify password endpoint (for security-sensitive operations)
app.post('/api/auth/verify-password', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ 
        success: false,
        valid: false,
        message: 'Password is required' 
      });
    }

    const userIdBinary = uuidToBinary(userId);

    // Get user's password hash
    const [users] = await pool.execute(
      'SELECT password_hash FROM users WHERE id = ?',
      [userIdBinary]
    );

    if (users.length === 0) {
      return res.status(404).json({ 
        success: false,
        valid: false,
        message: 'User not found' 
      });
    }

    const user = users[0];

    // Check if user has a password (social login users don't)
    if (!user.password_hash) {
      return res.status(400).json({ 
        success: false,
        valid: false,
        message: 'Password verification not available for social login accounts' 
      });
    }

    // Verify password
    const isValid = await bcrypt.compare(password, user.password_hash);

    res.json({ 
      success: true,
      valid: isValid
    });
  } catch (error) {
    console.error('Error verifying password:', error);
    res.status(500).json({ 
      success: false,
      valid: false,
      message: 'Server error' 
    });
  }
});

// ============================================================================
// Two-Factor Authentication (2FA) Endpoints
// ============================================================================

// Setup 2FA - Generate secret and QR code
app.post('/api/auth/2fa/setup', authenticateToken, async (req, res) => {
  try {
    const { userId, password } = req.body;

    if (!userId) {
      return res.status(400).json({ 
        success: false,
        message: 'User ID is required' 
      });
    }

    const userIdBinary = uuidToBinary(userId);
    const encryptionKey = getEncryptionKeyQuery();

    // Get user details including password and social login info
    const [users] = await pool.execute(
      `SELECT 
        id,
        CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email,
        two_factor_enabled,
        password_hash,
        google_id,
        facebook_id
       FROM users 
       WHERE id = ?`,
      [userIdBinary]
    );

    if (users.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    const user = users[0];
    
    // Check if this is a social login account (has google_id or facebook_id)
    const isSocialLogin = !!(user.google_id || user.facebook_id);

    // Verify password only for non-social login accounts
    if (!isSocialLogin) {
      // Regular account - password verification required
      if (!password) {
        return res.status(400).json({ 
          success: false,
          message: 'Password is required for security verification' 
        });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
      if (!isPasswordValid) {
        return res.status(401).json({ 
          success: false,
          message: 'Invalid password' 
        });
      }
    }
    // Social login accounts can proceed without password verification

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `Para App (${user.email})`,
      issuer: 'Para App',
      length: 32
    });

    // Store the secret temporarily - not enabled yet
    // Note: Storing without encryption since it's already protected by authentication
    // and encryption is causing issues with retrieval
    console.log('🔐 2FA Setup - Storing secret for user:', userId);
    console.log('🔐 2FA Setup - Secret (base32):', secret.base32);
    console.log('🔐 2FA Setup - Secret length:', secret.base32.length);
    
    await pool.execute(
      'UPDATE users SET two_factor_secret = ? WHERE id = ?',
      [secret.base32, userIdBinary]
    );
    
    // Verify it was stored
    const [check] = await pool.execute(
      'SELECT two_factor_secret FROM users WHERE id = ?',
      [userIdBinary]
    );
    console.log('🔐 2FA Setup - Secret stored successfully:', check[0].two_factor_secret !== null);
    console.log('🔐 2FA Setup - Stored secret matches:', check[0].two_factor_secret === secret.base32);

    // Return the TOTP URL for QR code generation on client side
    console.log('🔐 2FA Setup - otpauth_url:', secret.otpauth_url);
    console.log('🔐 2FA Setup - otpauth_url length:', secret.otpauth_url.length);
    
    res.json({
      success: true,
      secret: secret.base32,
      otpauthUrl: secret.otpauth_url,
      message: 'Scan the QR code with your authenticator app'
    });
  } catch (error) {
    console.error('Error setting up 2FA:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// Verify and enable 2FA
app.post('/api/auth/2fa/verify', authenticateToken, async (req, res) => {
  try {
    const { userId, token } = req.body;

    if (!userId || !token) {
      return res.status(400).json({ 
        success: false,
        message: 'User ID and verification token are required' 
      });
    }

    const userIdBinary = uuidToBinary(userId);
    const encryptionKey = getEncryptionKeyQuery();

    // Get user's secret (stored without encryption for reliability)
    const [users] = await pool.execute(
      `SELECT 
        id,
        two_factor_secret
       FROM users 
       WHERE id = ?`,
      [userIdBinary]
    );

    console.log('🔐 2FA Verify - User found:', users.length > 0);
    console.log('🔐 2FA Verify - Has secret:', users.length > 0 && users[0].two_factor_secret !== null);
    console.log('🔐 2FA Verify - Secret:', users.length > 0 ? users[0].two_factor_secret : 'N/A');
    console.log('🔐 2FA Verify - Secret length:', users.length > 0 && users[0].two_factor_secret ? users[0].two_factor_secret.length : 0);

    if (users.length === 0 || !users[0].two_factor_secret) {
      return res.status(400).json({ 
        success: false,
        message: '2FA setup not initiated. Please go back and scan the QR code again.' 
      });
    }

    const user = users[0];

    // Verify the token
    const verified = speakeasy.totp.verify({
      secret: user.two_factor_secret,
      encoding: 'base32',
      token: token,
      window: 2 // Allow 2 time steps before/after for clock skew
    });

    if (!verified) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid verification code' 
      });
    }

    // Generate backup codes
    const backupCodes = [];
    for (let i = 0; i < 10; i++) {
      backupCodes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
    }

    // Hash backup codes and store with metadata
    const hashedBackupCodes = await Promise.all(
      backupCodes.map(async (code) => ({
        code: code, // Store plain code (will be shown to user)
        hash: await bcrypt.hash(code, 10), // Store hash for verification
        used: false
      }))
    );

    console.log('🔐 Storing backup codes...');
    console.log('🔐 Plain codes count:', backupCodes.length);
    console.log('🔐 Hashed codes count:', hashedBackupCodes.length);
    console.log('🔐 Sample structure:', JSON.stringify(hashedBackupCodes[0], null, 2));
    console.log('🔐 JSON string length:', JSON.stringify(hashedBackupCodes).length);

    // Enable 2FA and store backup codes with metadata
    await pool.execute(
      'UPDATE users SET two_factor_enabled = TRUE, backup_codes = ? WHERE id = ?',
      [JSON.stringify(hashedBackupCodes), userIdBinary]
    );
    
    console.log('✅ Backup codes stored successfully');

    res.json({
      success: true,
      message: '2FA enabled successfully!',
      backupCodes: backupCodes // Return plain codes to user (only shown once)
    });
  } catch (error) {
    console.error('Error verifying 2FA:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// Disable 2FA
app.post('/api/auth/2fa/disable', authenticateToken, async (req, res) => {
  try {
    const { userId, password } = req.body;

    if (!userId || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'User ID and password are required' 
      });
    }

    const userIdBinary = uuidToBinary(userId);

    // Verify password before disabling 2FA
    const [users] = await pool.execute(
      'SELECT id, password_hash FROM users WHERE id = ?',
      [userIdBinary]
    );

    if (users.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(400).json({ 
        success: false,
        message: 'Incorrect password' 
      });
    }

    // Disable 2FA and clear secret and backup codes
    await pool.execute(
      'UPDATE users SET two_factor_enabled = FALSE, two_factor_secret = NULL, backup_codes = NULL WHERE id = ?',
      [userIdBinary]
    );

    res.json({
      success: true,
      message: '2FA disabled successfully'
    });
  } catch (error) {
    console.error('Error disabling 2FA:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// Verify 2FA token during login
app.post('/api/auth/2fa/validate', async (req, res) => {
  try {
    const { userId, token, isBackupCode } = req.body;

    if (!userId || !token) {
      return res.status(400).json({ 
        success: false,
        message: 'User ID and token are required' 
      });
    }

    const userIdBinary = uuidToBinary(userId);
    const encryptionKey = getEncryptionKeyQuery();

    // Get user's 2FA data
    const [users] = await pool.execute(
      `SELECT 
        id,
        two_factor_enabled,
        two_factor_secret,
        CAST(AES_DECRYPT(backup_codes, ${encryptionKey}) AS CHAR) as backup_codes
       FROM users 
       WHERE id = ?`,
      [userIdBinary]
    );

    if (users.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    const user = users[0];

    if (!user.two_factor_enabled) {
      return res.status(400).json({ 
        success: false,
        message: '2FA is not enabled for this account' 
      });
    }

    let verified = false;

    if (isBackupCode) {
      // Verify backup code
      if (!user.backup_codes) {
        return res.status(400).json({ 
          success: false,
          message: 'No backup codes available' 
        });
      }

      const backupCodes = JSON.parse(user.backup_codes);
      
      // Check if any backup code matches
      for (let i = 0; i < backupCodes.length; i++) {
        const codeObj = backupCodes[i];
        
        // Handle both old format (string) and new format (object)
        const hash = typeof codeObj === 'string' ? codeObj : codeObj.hash;
        const isUsed = typeof codeObj === 'object' && codeObj.used;
        
        if (isUsed) {
          continue;
        }
        
        const isMatch = await bcrypt.compare(token, hash);
        if (isMatch) {
          verified = true;
          
          // Mark code as used
          if (typeof codeObj === 'object') {
            backupCodes[i].used = true;
          } else {
            // Old format: remove the code
            backupCodes.splice(i, 1);
          }
          
          await pool.execute(
            'UPDATE users SET backup_codes = ? WHERE id = ?',
            [JSON.stringify(backupCodes), userIdBinary]
          );
          break;
        }
      }
    } else {
      // Verify TOTP token
      verified = speakeasy.totp.verify({
        secret: user.two_factor_secret,
        encoding: 'base32',
        token: token,
        window: 2
      });
    }

    if (!verified) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid verification code' 
      });
    }

    res.json({
      success: true,
      message: '2FA verification successful'
    });
  } catch (error) {
    console.error('Error validating 2FA:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// Complete login with 2FA verification
app.post('/api/auth/2fa/login', async (req, res) => {
  try {
    const { userId, token, isBackupCode } = req.body;

    if (!userId || !token) {
      return res.status(400).json({ 
        success: false,
        message: 'User ID and verification code are required' 
      });
    }

    const userIdBinary = uuidToBinary(userId);
    const encryptionKey = getEncryptionKeyQuery();

    // Get user's 2FA data
    const [users] = await pool.execute(
      `SELECT 
        id,
        CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) as full_name,
        CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email,
        avatar_url,
        email_verified,
        two_factor_enabled,
        two_factor_secret,
        backup_codes
       FROM users 
       WHERE id = ?`,
      [userIdBinary]
    );

    if (users.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    const user = users[0];
    const userUuid = binaryToUuid(user.id);

    if (!user.two_factor_enabled) {
      return res.status(400).json({ 
        success: false,
        message: '2FA is not enabled for this account' 
      });
    }

    let verified = false;

    if (isBackupCode) {
      // Verify backup code
      console.log('🔐 Backup code verification requested');
      console.log('🔐 user.backup_codes exists:', !!user.backup_codes);
      console.log('🔐 user.backup_codes type:', typeof user.backup_codes);
      
      if (!user.backup_codes) {
        console.log('❌ No backup codes in database');
        return res.status(400).json({ 
          success: false,
          message: 'No backup codes available. Please contact support or use your authenticator app.' 
        });
      }

      let backupCodes;
      try {
        backupCodes = JSON.parse(user.backup_codes);
        console.log('✅ Backup codes parsed successfully, count:', backupCodes.length);
      } catch (e) {
        console.log('❌ Failed to parse backup codes:', e.message);
        console.log('❌ Raw backup_codes value:', user.backup_codes.substring(0, 100));
        return res.status(400).json({ 
          success: false,
          message: 'Backup codes are corrupted. Please disable and re-enable 2FA.' 
        });
      }
      
      if (backupCodes.length === 0) {
        console.log('❌ No backup codes remaining');
        return res.status(400).json({ 
          success: false,
          message: 'All backup codes have been used. Please use your authenticator app or disable and re-enable 2FA to generate new codes.' 
        });
      }
      
      // Check if any backup code matches
      console.log(`🔐 Checking ${backupCodes.length} backup codes...`);
      for (let i = 0; i < backupCodes.length; i++) {
        const codeObj = backupCodes[i];
        
        // Handle both old format (string) and new format (object)
        const hash = typeof codeObj === 'string' ? codeObj : codeObj.hash;
        const isUsed = typeof codeObj === 'object' && codeObj.used;
        
        if (isUsed) {
          console.log(`⏭️  Skipping used code at index ${i}`);
          continue;
        }
        
        const isMatch = await bcrypt.compare(token, hash);
        if (isMatch) {
          console.log(`✅ Backup code matched at index ${i}`);
          verified = true;
          
          // Mark code as used (don't remove it so user can see it was used)
          if (typeof codeObj === 'object') {
            backupCodes[i].used = true;
          } else {
            // Old format: remove the code
            backupCodes.splice(i, 1);
          }
          
          console.log(`🔐 Remaining unused codes: ${backupCodes.filter(c => typeof c === 'string' || !c.used).length}`);
          await pool.execute(
            'UPDATE users SET backup_codes = ? WHERE id = ?',
            [JSON.stringify(backupCodes), userIdBinary]
          );
          break;
        }
      }
      
      if (!verified) {
        console.log('❌ No backup code matched');
      }
    } else {
      // Verify TOTP token
      verified = speakeasy.totp.verify({
        secret: user.two_factor_secret,
        encoding: 'base32',
        token: token,
        window: 2
      });
      
      if (verified) {
        console.log('✅ TOTP token verified');
      } else {
        console.log('❌ TOTP token verification failed');
      }
    }

    if (!verified) {
      return res.status(400).json({ 
        success: false,
        message: isBackupCode ? 'Invalid backup code' : 'Invalid verification code' 
      });
    }

    // Generate full JWT token
    const jwtToken = jwt.sign(
      { userId: userUuid, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token: jwtToken,
      user: {
        id: userUuid,
        fullName: user.full_name,
        email: user.email,
        avatarUrl: user.avatar_url || null,
        emailVerified: user.email_verified || false,
        twoFactorEnabled: user.two_factor_enabled || false
      }
    });
  } catch (error) {
    console.error('Error completing 2FA login:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// Complete 2FA login with biometric (bypass TOTP code)
app.post('/api/auth/2fa/login/biometric', async (req, res) => {
  try {
    const { userId } = req.body;

    console.log('🔐 2FA biometric login request for user:', userId);

    if (!userId) {
      return res.status(400).json({ 
        success: false,
        message: 'User ID is required' 
      });
    }

    const userIdBinary = uuidToBinary(userId);
    const encryptionKey = getEncryptionKeyQuery();

    // Get user data
    const [users] = await pool.execute(
      `SELECT 
        id,
        CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) as full_name,
        CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email,
        avatar_url,
        email_verified,
        two_factor_enabled
       FROM users 
       WHERE id = ?`,
      [userIdBinary]
    );

    if (users.length === 0) {
      console.log('❌ User not found');
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    const user = users[0];
    const userUuid = binaryToUuid(user.id);

    if (!user.two_factor_enabled) {
      console.log('❌ 2FA not enabled for user');
      return res.status(400).json({ 
        success: false,
        message: '2FA is not enabled for this account' 
      });
    }

    console.log('✅ User verified, generating token');

    // Generate full JWT token (biometric already verified on client side)
    const jwtToken = jwt.sign(
      { userId: userUuid, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    console.log('✅ 2FA biometric login successful');

    res.json({
      success: true,
      message: 'Login successful with biometric',
      token: jwtToken,
      user: {
        id: userUuid,
        fullName: user.full_name,
        email: user.email,
        avatarUrl: user.avatar_url || null,
        emailVerified: user.email_verified || false,
        twoFactorEnabled: user.two_factor_enabled || false
      }
    });
  } catch (error) {
    console.error('Error completing 2FA biometric login:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// Get 2FA status
app.get('/api/auth/2fa/status/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const userIdBinary = uuidToBinary(userId);

    const [users] = await pool.execute(
      'SELECT two_factor_enabled FROM users WHERE id = ?',
      [userIdBinary]
    );

    if (users.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    res.json({
      success: true,
      enabled: users[0].two_factor_enabled || false
    });
  } catch (error) {
    console.error('Error getting 2FA status:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

// Get backup codes
app.post('/api/auth/2fa/backup-codes', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userIdBinary = uuidToBinary(userId);
    const { password } = req.body;

    // Get user with password, 2FA status, and social login info
    const [users] = await pool.execute(
      'SELECT two_factor_enabled, password_hash, backup_codes, google_id, facebook_id FROM users WHERE id = ?',
      [userIdBinary]
    );

    if (users.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    const user = users[0];

    if (!user.two_factor_enabled) {
      return res.status(400).json({ 
        success: false,
        message: '2FA is not enabled' 
      });
    }

    // Check if this is a social login account (has google_id or facebook_id)
    const isSocialLogin = !!(user.google_id || user.facebook_id);

    // Verify password only for non-social login accounts
    if (!isSocialLogin) {
      // Regular account - password verification required
      if (!password) {
        return res.status(400).json({ 
          success: false,
          message: 'Password is required' 
        });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
      if (!isPasswordValid) {
        return res.status(401).json({ 
          success: false,
          message: 'Invalid password' 
        });
      }
    }
    // Social login accounts can proceed without password verification

    if (!user.backup_codes) {
      return res.json({
        success: true,
        backupCodes: []
      });
    }

    // Parse backup codes JSON
    const backupCodes = JSON.parse(user.backup_codes);

    // Filter and format codes
    // Handle both old format (array of strings) and new format (array of objects)
    const validCodes = backupCodes
      .filter(c => c != null)
      .map(c => {
        // Old format: just a hash string (can't show to user)
        if (typeof c === 'string') {
          return null; // Can't display hashed codes
        }
        // New format: object with code, hash, and used flag
        if (c.code && typeof c.code === 'string') {
          return {
            code: c.code,
            used: c.used || false
          };
        }
        return null;
      })
      .filter(c => c !== null);

    res.json({
      success: true,
      backupCodes: validCodes
    });
  } catch (error) {
    console.error('Error getting backup codes:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error' 
    });
  }
});

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0'; // allow external access

// ============================================================================
// Enhanced Chat Endpoints - Support NLU, Sentiment Analysis, and Context
// ============================================================================

// Helper function to update session activity
async function updateSessionActivity(sessionId, userIdBinary) {
  try {
    await pool.execute(`
      INSERT INTO conversation_sessions (id, user_id, message_count, last_activity)
      VALUES (?, ?, 1, NOW())
      ON DUPLICATE KEY UPDATE
      message_count = message_count + 1,
      last_activity = NOW()
    `, [sessionId, userIdBinary]);
  } catch (error) {
    console.error('Error updating session activity:', error);
  }
}

// Helper function to update conversation analytics
async function updateConversationAnalytics(userId, sessionId, isBot, sentiment) {
  try {
    const today = new Date().toISOString().split('T')[0];
    
    await pool.execute(`
      INSERT INTO conversation_analytics 
      (user_id, session_id, date, total_messages, user_messages, bot_messages)
      VALUES (?, ?, ?, 1, ?, ?)
      ON DUPLICATE KEY UPDATE
      total_messages = total_messages + 1,
      user_messages = user_messages + ?,
      bot_messages = bot_messages + ?
    `, [
      uuidToBinary(userId),
      sessionId,
      today,
      isBot ? 0 : 1,
      isBot ? 1 : 0,
      isBot ? 0 : 1,
      isBot ? 1 : 0
    ]);
  } catch (error) {
    console.error('Error updating analytics:', error);
  }
}

// Get messages with enhanced data for a user
app.get('/api/chats/:userId/messages/enhanced', optionalAuthenticateToken, async (req, res) => {
  try {
    const userIdParam = req.params.userId;
    const { sessionId, limit = 50, offset = 0 } = req.query;
    
    console.log(`[GET Enhanced Messages] Request for userId: ${userIdParam}, sessionId: ${sessionId}`);
    
    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(userIdParam)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    // If JWT token is provided, verify userId matches authenticated user
    if (req.user && req.user.userId !== userIdParam) {
      return res.status(403).json({ message: 'Access denied: User ID mismatch' });
    }

    const userIdBinary = uuidToBinary(userIdParam);

    // Build query with optional session filter
    let query = `
      SELECT id, user_id, text, is_bot as isBot, timestamp, error, 
             intent, sentiment, confidence, entities, metadata, session_id
      FROM messages 
      WHERE user_id = ?
    `;
    const params = [userIdBinary];

    if (sessionId) {
      query += ' AND session_id = ?';
      params.push(sessionId);
    }

    query += ' ORDER BY timestamp ASC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const [rows] = await pool.execute(query, params);

    // Format response with enhanced data
    const formattedRows = rows.map(row => ({
      id: row.id,
      userId: binaryToUuid(row.user_id) || userIdParam,
      text: row.text,
      isBot: row.isBot === 1 || row.isBot === true,
      timestamp: row.timestamp ? new Date(row.timestamp).toISOString() : new Date().toISOString(),
      error: row.error,
      intent: row.intent,
      sentiment: row.sentiment,
      confidence: row.confidence,
      entities: row.entities ? JSON.parse(row.entities) : null,
      metadata: row.metadata ? JSON.parse(row.metadata) : null,
      sessionId: row.session_id
    }));

    res.json({
      messages: formattedRows,
      total: formattedRows.length,
      sessionId: sessionId
    });
  } catch (error) {
    console.error('[GET Enhanced Messages] Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Post enhanced message with NLU and sentiment data
app.post('/api/chats/:userId/messages/enhanced', optionalAuthenticateToken, async (req, res) => {
  try {
    const userIdParam = req.params.userId;
    const { 
      text, 
      isBot, 
      error, 
      intent, 
      sentiment, 
      confidence, 
      entities, 
      metadata, 
      sessionId 
    } = req.body;
    
    console.log(`[POST Enhanced Message] Request for userId: ${userIdParam}, sessionId: ${sessionId}`);
    
    // Validate required fields
    if (!text || typeof isBot !== 'boolean') {
      return res.status(400).json({ message: 'Text and isBot are required' });
    }

    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(userIdParam)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    // If JWT token is provided, verify userId matches authenticated user
    if (req.user && req.user.userId !== userIdParam) {
      return res.status(403).json({ message: 'Access denied: User ID mismatch' });
    }

    const userIdBinary = uuidToBinary(userIdParam);

    // Verify user exists
    const [userCheck] = await pool.execute(
      'SELECT id FROM users WHERE id = ?',
      [userIdBinary]
    );
    if (userCheck.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Create or update session if provided
    if (sessionId && isBot === false) { // Only update session for user messages
      await updateSessionActivity(sessionId, userIdBinary);
    }

    // Insert enhanced message
    const [result] = await pool.execute(`
      INSERT INTO messages 
      (user_id, text, is_bot, error, intent, sentiment, confidence, entities, metadata, session_id, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `, [
      userIdBinary,
      text,
      isBot ? 1 : 0,
      error || null,
      intent || null,
      sentiment || null,
      confidence || null,
      entities ? JSON.stringify(entities) : null,
      metadata ? JSON.stringify(metadata) : null,
      sessionId || null
    ]);

    // Update analytics
    await updateConversationAnalytics(userIdParam, sessionId, isBot, sentiment);

    res.json({
      id: result.insertId,
      message: 'Message saved successfully',
      sessionId: sessionId
    });
  } catch (error) {
    console.error('[POST Enhanced Message] Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create or update conversation session
app.post('/api/chats/:userId/sessions', optionalAuthenticateToken, async (req, res) => {
  try {
    const userIdParam = req.params.userId;
    const { sessionId, context, preferences } = req.body;
    
    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(userIdParam)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    // If JWT token is provided, verify userId matches authenticated user
    if (req.user && req.user.userId !== userIdParam) {
      return res.status(403).json({ message: 'Access denied: User ID mismatch' });
    }

    const userIdBinary = uuidToBinary(userIdParam);

    // Generate session ID if not provided
    const finalSessionId = sessionId || generateUUID();

    // Insert or update session
    await pool.execute(`
      INSERT INTO conversation_sessions 
      (id, user_id, context, preferences, started_at, last_activity)
      VALUES (?, ?, ?, ?, NOW(), NOW())
      ON DUPLICATE KEY UPDATE
      context = VALUES(context),
      preferences = VALUES(preferences),
      last_activity = NOW()
    `, [
      finalSessionId,
      userIdBinary,
      context ? JSON.stringify(context) : null,
      preferences ? JSON.stringify(preferences) : null
    ]);

    res.json({
      sessionId: finalSessionId,
      message: 'Session created/updated successfully'
    });
  } catch (error) {
    console.error('[POST Session] Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get conversation session
app.get('/api/chats/:userId/sessions/:sessionId', optionalAuthenticateToken, async (req, res) => {
  try {
    const { userId, sessionId } = req.params;
    
    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(userId)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    // If JWT token is provided, verify userId matches authenticated user
    if (req.user && req.user.userId !== userId) {
      return res.status(403).json({ message: 'Access denied: User ID mismatch' });
    }

    const userIdBinary = uuidToBinary(userId);

    const [rows] = await pool.execute(`
      SELECT id, user_id, started_at, last_activity, message_count, context, preferences
      FROM conversation_sessions 
      WHERE id = ? AND user_id = ?
    `, [sessionId, userIdBinary]);

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Session not found' });
    }

    const session = rows[0];
    res.json({
      sessionId: session.id,
      userId: binaryToUuid(session.user_id),
      startedAt: session.started_at,
      lastActivity: session.last_activity,
      messageCount: session.message_count,
      context: session.context ? JSON.parse(session.context) : null,
      preferences: session.preferences ? JSON.parse(session.preferences) : null
    });
  } catch (error) {
    console.error('[GET Session] Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update user preferences
app.post('/api/chats/:userId/preferences', optionalAuthenticateToken, async (req, res) => {
  try {
    const userIdParam = req.params.userId;
    const { preferences } = req.body; // Object with key-value pairs
    
    if (!preferences || typeof preferences !== 'object') {
      return res.status(400).json({ message: 'Preferences object is required' });
    }

    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(userIdParam)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    // If JWT token is provided, verify userId matches authenticated user
    if (req.user && req.user.userId !== userIdParam) {
      return res.status(403).json({ message: 'Access denied: User ID mismatch' });
    }

    const userIdBinary = uuidToBinary(userIdParam);

    // Batch insert/update preferences
    const insertPromises = Object.entries(preferences).map(([key, value]) =>
      pool.execute(`
        INSERT INTO user_chat_preferences (user_id, preference_key, preference_value)
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE
        preference_value = VALUES(preference_value),
        updated_at = NOW()
      `, [userIdBinary, key, JSON.stringify(value)])
    );

    await Promise.all(insertPromises);

    res.json({
      message: 'Preferences updated successfully',
      preferences: preferences
    });
  } catch (error) {
    console.error('[POST Preferences] Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user preferences
app.get('/api/chats/:userId/preferences', optionalAuthenticateToken, async (req, res) => {
  try {
    const userIdParam = req.params.userId;
    
    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(userIdParam)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    // If JWT token is provided, verify userId matches authenticated user
    if (req.user && req.user.userId !== userIdParam) {
      return res.status(403).json({ message: 'Access denied: User ID mismatch' });
    }

    const userIdBinary = uuidToBinary(userIdParam);

    const [rows] = await pool.execute(`
      SELECT preference_key, preference_value
      FROM user_chat_preferences
      WHERE user_id = ?
    `, [userIdBinary]);

    const preferences = {};
    rows.forEach(row => {
      preferences[row.preference_key] = JSON.parse(row.preference_value);
    });

    res.json(preferences);
  } catch (error) {
    console.error('[GET Preferences] Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ============================================================================
// Biometric Authentication Endpoints
// ============================================================================

// Enable biometric authentication for user
app.post('/api/auth/biometric/enable', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { password } = req.body;
    const userIdBinary = uuidToBinary(userId);

    // Get user password and social login info
    const [users] = await pool.execute(
      'SELECT password_hash, google_id, facebook_id FROM users WHERE id = ?',
      [userIdBinary]
    );

    if (users.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    const user = users[0];
    
    // Check if this is a social login account (has google_id or facebook_id)
    const isSocialLogin = !!(user.google_id || user.facebook_id);

    // Verify password only for non-social login accounts
    if (!isSocialLogin) {
      // Regular account - password verification required
      if (!password) {
        return res.status(400).json({ 
          success: false,
          message: 'Password is required for security verification' 
        });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
      if (!isPasswordValid) {
        return res.status(401).json({ 
          success: false,
          message: 'Invalid password' 
        });
      }
    }
    // Social login accounts can proceed without password verification

    // Update user's biometric_enabled status
    await pool.execute(
      'UPDATE users SET biometric_enabled = TRUE WHERE id = ?',
      [userIdBinary]
    );

    res.json({
      success: true,
      message: 'Biometric authentication enabled successfully'
    });
  } catch (error) {
    console.error('Error enabling biometric:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to enable biometric authentication'
    });
  }
});

// Disable biometric authentication for user
app.post('/api/auth/biometric/disable', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userIdBinary = uuidToBinary(userId);

    // Update user's biometric_enabled status
    await pool.execute(
      'UPDATE users SET biometric_enabled = FALSE WHERE id = ?',
      [userIdBinary]
    );

    res.json({
      success: true,
      message: 'Biometric authentication disabled successfully'
    });
  } catch (error) {
    console.error('Error disabling biometric:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to disable biometric authentication'
    });
  }
});

// Get biometric status for user
app.get('/api/auth/biometric/status', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userIdBinary = uuidToBinary(userId);

    const [rows] = await pool.execute(
      'SELECT biometric_enabled FROM users WHERE id = ?',
      [userIdBinary]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      enabled: rows[0].biometric_enabled === 1
    });
  } catch (error) {
    console.error('Error getting biometric status:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get biometric status'
    });
  }
});

// Validate token for biometric login
app.post('/api/auth/biometric/validate', async (req, res) => {
  try {
    const { token } = req.body;

    console.log('🔐 Biometric validate request received');
    console.log('Token:', token ? token.substring(0, 50) + '...' : 'null');

    if (!token) {
      console.log('❌ No token provided');
      return res.status(400).json({
        success: false,
        message: 'Token is required'
      });
    }

    // Verify JWT token
    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
      if (err) {
        console.log('❌ JWT verification failed:', err.message);
        return res.status(401).json({
          success: false,
          message: 'Invalid or expired token'
        });
      }

      console.log('✅ JWT verified successfully');
      console.log('User ID:', decoded.userId);

      try {
        const userId = decoded.userId;
        const userIdBinary = uuidToBinary(userId);

        const encryptionKey = getEncryptionKeyQuery();

        // Get user data (using HEX instead of BIN_TO_UUID for MySQL 5.7 compatibility)
        const [rows] = await pool.execute(
          `SELECT HEX(id) as id, 
                  CAST(AES_DECRYPT(full_name, ${encryptionKey}) AS CHAR) as full_name,
                  CAST(AES_DECRYPT(email, ${encryptionKey}) AS CHAR) as email,
                  avatar_url, 
                  email_verified,
                  two_factor_enabled, 
                  biometric_enabled, 
                  created_at
           FROM users 
           WHERE id = ?`,
          [userIdBinary]
        );

        if (rows.length === 0) {
          console.log('❌ User not found in database');
          return res.status(404).json({
            success: false,
            message: 'User not found'
          });
        }

        const user = rows[0];
        // Convert HEX back to UUID format
        const hexId = user.id;
        const formattedId = `${hexId.substr(0,8)}-${hexId.substr(8,4)}-${hexId.substr(12,4)}-${hexId.substr(16,4)}-${hexId.substr(20,12)}`.toLowerCase();
        
        console.log('✅ User found:', user.email);
        console.log('Biometric enabled in DB:', user.biometric_enabled);

        // Update last biometric login timestamp
        await pool.execute(
          'UPDATE users SET last_biometric_login = NOW() WHERE id = ?',
          [userIdBinary]
        );

        console.log('✅ Sending success response');
        res.json({
          success: true,
          user: {
            id: formattedId,
            fullName: user.full_name,
            email: user.email,
            avatarUrl: user.avatar_url || null,
            emailVerified: user.email_verified || false,
            twoFactorEnabled: user.two_factor_enabled === 1,
            biometricEnabled: user.biometric_enabled === 1,
            createdAt: user.created_at
          },
          token: token
        });
      } catch (error) {
        console.error('Error validating token:', error);
        res.status(500).json({
          success: false,
          message: 'Server error'
        });
      }
    });
  } catch (error) {
    console.error('Error in biometric validation:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to validate biometric login'
    });
  }
});

app.listen(PORT, HOST, () => {
  console.log(`🚀 Backend server running on http://${HOST}:${PORT}`);
  console.log(`📝 API endpoints available at http://${HOST}:${PORT}/api`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🗄️  Database: ${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || 3306}/${process.env.DB_NAME || 'para_db'}`);
  console.log(`🤖 Enhanced chat features enabled`);
  ensureAvatarColumn();
});

// =============================
// Biometric 2FA Endpoints
// =============================

// Enable biometric for 2FA
app.post('/api/auth/biometric/2fa/enable', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userIdBinary = uuidToBinary(userId);

    // Update user's biometric_2fa_enabled status
    await pool.execute(
      'UPDATE users SET biometric_2fa_enabled = TRUE WHERE id = ?',
      [userIdBinary]
    );

    res.json({
      success: true,
      message: 'Biometric 2FA enabled successfully'
    });
  } catch (error) {
    console.error('Error enabling biometric 2FA:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to enable biometric 2FA'
    });
  }
});

// Disable biometric for 2FA
app.post('/api/auth/biometric/2fa/disable', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userIdBinary = uuidToBinary(userId);

    // Update user's biometric_2fa_enabled status
    await pool.execute(
      'UPDATE users SET biometric_2fa_enabled = FALSE WHERE id = ?',
      [userIdBinary]
    );

    res.json({
      success: true,
      message: 'Biometric 2FA disabled successfully'
    });
  } catch (error) {
    console.error('Error disabling biometric 2FA:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to disable biometric 2FA'
    });
  }
});

// Get biometric 2FA status
app.get('/api/auth/biometric/2fa/status', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userIdBinary = uuidToBinary(userId);

    const [rows] = await pool.execute(
      'SELECT biometric_2fa_enabled FROM users WHERE id = ?',
      [userIdBinary]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      enabled: rows[0].biometric_2fa_enabled === 1
    });
  } catch (error) {
    console.error('Error getting biometric 2FA status:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get biometric 2FA status'
    });
  }
});

// Get biometric 2FA status for a specific user (during login flow, no auth required)
app.get('/api/auth/biometric/2fa/status/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const userIdBinary = uuidToBinary(userId);

    const [rows] = await pool.execute(
      'SELECT biometric_2fa_enabled FROM users WHERE id = ?',
      [userIdBinary]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      enabled: rows[0].biometric_2fa_enabled === 1
    });
  } catch (error) {
    console.error('Error getting biometric 2FA status for user:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get biometric 2FA status'
    });
  }
});

// =============================
// Privacy Preferences Endpoint
// =============================

// Update privacy preferences (analytics)
app.put('/api/users/privacy-preferences', authenticateToken, async (req, res) => {
  try {
    const { preferenceType, enabled } = req.body;
    const userId = req.user.userId;

    if (!preferenceType || enabled === undefined) {
      return res.status(400).json({ 
        message: 'preferenceType and enabled are required' 
      });
    }

    // Validate preference type
    const validTypes = ['analytics'];
    if (!validTypes.includes(preferenceType)) {
      return res.status(400).json({ 
        message: 'Invalid preference type. Must be analytics' 
      });
    }

    const userIdBinary = uuidToBinary(userId);

    // Check if user_preferences table exists, if not create it
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS user_preferences (
        user_id BINARY(16) PRIMARY KEY,
        analytics TINYINT(1) DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Insert or update preference
    await pool.execute(`
      INSERT INTO user_preferences (user_id, ${preferenceType}, updated_at)
      VALUES (?, ?, NOW())
      ON DUPLICATE KEY UPDATE ${preferenceType} = ?, updated_at = NOW()
    `, [userIdBinary, enabled ? 1 : 0, enabled ? 1 : 0]);

    res.json({ 
      success: true, 
      message: 'Privacy preference updated successfully' 
    });
  } catch (error) {
    console.error('Error updating privacy preference:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get privacy preferences
app.get('/api/users/privacy-preferences', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userIdBinary = uuidToBinary(userId);

    const [rows] = await pool.execute(
      'SELECT analytics FROM user_preferences WHERE user_id = ?',
      [userIdBinary]
    );

    if (rows.length === 0) {
      // Return defaults if no preferences set
      return res.json({
        analytics: true
      });
    }

    res.json({
      analytics: rows[0].analytics === 1
    });
  } catch (error) {
    console.error('Error getting privacy preferences:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// =============================
// Account Deletion Endpoint
// =============================

// Delete user account
app.delete('/api/users/account', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { password } = req.body;
    const userIdBinary = uuidToBinary(userId);

    // Get user details
    const encryptionKey = getEncryptionKeyQuery();
    const [users] = await pool.execute(
      `SELECT 
        password_hash,
        google_id,
        facebook_id
       FROM users 
       WHERE id = ?`,
      [userIdBinary]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = users[0];
    const isSocialLogin = !!(user.google_id || user.facebook_id);

    // For email users, verify password
    if (!isSocialLogin) {
      if (!password) {
        return res.status(400).json({ 
          message: 'Password is required to delete account' 
        });
      }

      const isMatch = await bcrypt.compare(password, user.password_hash);
      if (!isMatch) {
        return res.status(400).json({ message: 'Incorrect password' });
      }
    }

    // Delete user account (CASCADE will delete related data)
    await pool.execute('DELETE FROM users WHERE id = ?', [userIdBinary]);

    res.json({ 
      success: true, 
      message: 'Account deleted successfully' 
    });
  } catch (error) {
    console.error('Error deleting account:', error);
    res.status(500).json({ message: 'Server error' });
  }
});
