require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const stream = require('stream');
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
        password_hash,
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
          lockedUntil: lockUntil
        });
      }

      const remainingAttempts = MAX_FAILED_ATTEMPTS - newAttempts;
      return res.status(400).json({ 
        message: `Invalid credentials. ${remainingAttempts} attempt(s) remaining before account lock.`
      });
    }

    // Successful login - reset failed attempts and update last login
    await pool.execute(
      'UPDATE users SET failed_login_attempts = 0, is_locked = 0, locked_until = NULL, last_login_attempt = ? WHERE id = ?',
      [now, userIdBinary]
    );

    // Generate token using UUID string
    const token = jwt.sign(
      { userId: userUuid, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: userUuid,
        fullName: user.full_name,
        email: user.email,
        avatarUrl: user.avatar_url || null
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
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
              created_at, updated_at
       FROM users WHERE id = ?`,
      [uuidToBinary(id)]
    );
    if (rows.length === 0) return res.status(404).json({ message: 'User not found' });
    const u = rows[0];
    res.json({
      id: binaryToUuid(u.id),
      fullName: u.full_name,
      email: u.email,
      avatarUrl: u.avatar_url || null,
      createdAt: u.created_at,
      updatedAt: u.updated_at,
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
    if (fullName) {
      fields.push(`full_name = AES_ENCRYPT(?, ${encryptionKey})`);
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

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0'; // allow external access

app.listen(PORT, HOST, () => {
  console.log(`🚀 Backend server running on http://${HOST}:${PORT}`);
  console.log(`📝 API endpoints available at http://${HOST}:${PORT}/api`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🗄️  Database: ${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || 3306}/${process.env.DB_NAME || 'para_db'}`);
  ensureAvatarColumn();
});
