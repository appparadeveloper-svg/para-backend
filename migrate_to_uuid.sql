-- Migration script to convert existing database from INT to UUID
-- BACKUP YOUR DATABASE BEFORE RUNNING THIS!

USE para_db;

-- Generate encryption key (should match server.js)
SET @encryption_key = UNHEX(SHA2('b5c2a8d4f9e7b1a6d2e3c7f8a9b4c6d5f0a1b2e3c4d5e6f7a8b9c0d1e2f3a4', 256));

-- Step 1: Create temporary table with UUID structure
CREATE TABLE IF NOT EXISTS users_new (
    id BINARY(16) PRIMARY KEY,
    full_name VARBINARY(255) NOT NULL,
    email VARBINARY(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_locked TINYINT(1) NOT NULL DEFAULT 0,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIME DEFAULT NULL,
    last_login_attempt DATETIME DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_email (email(255))
);

-- Step 2: Migrate existing data (encrypt names and emails)
INSERT INTO users_new (
    id,
    full_name,
    email,
    password_hash,
    created_at,
    updated_at
)
SELECT 
    UUID_TO_BIN(UUID()) as id,
    AES_ENCRYPT(full_name, @encryption_key) as full_name,
    AES_ENCRYPT(email, @encryption_key) as email,
    password_hash,
    created_at,
    updated_at
FROM users;

-- Step 3: Create mapping table to track old_id -> new_id
CREATE TEMPORARY TABLE id_mapping AS
SELECT 
    old_users.id as old_id,
    new_users.id as new_id
FROM users old_users
INNER JOIN users_new new_users ON 
    CAST(AES_DECRYPT(new_users.email, @encryption_key) AS CHAR) = old_users.email;

-- Step 4: Update messages table to use new UUIDs
-- First, create new messages table
CREATE TABLE IF NOT EXISTS messages_new (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BINARY(16) NOT NULL,
  text TEXT NOT NULL,
  is_bot TINYINT(1) NOT NULL DEFAULT 0,
  timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  error TEXT DEFAULT NULL,
  PRIMARY KEY (id),
  INDEX idx_user (user_id),
  CONSTRAINT fk_user_new
    FOREIGN KEY (user_id)
    REFERENCES users_new(id)
    ON DELETE CASCADE
);

-- Migrate messages with new user IDs
INSERT INTO messages_new (user_id, text, is_bot, timestamp, error)
SELECT 
    mapping.new_id,
    m.text,
    m.is_bot,
    m.timestamp,
    m.error
FROM messages m
INNER JOIN id_mapping mapping ON m.user_id = mapping.old_id;

-- Step 5: Drop old tables and rename new ones
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS users;

RENAME TABLE users_new TO users;
RENAME TABLE messages_new TO messages;

-- Clean up
DROP TEMPORARY TABLE IF EXISTS id_mapping;

SELECT 'Migration completed successfully!' as status;

