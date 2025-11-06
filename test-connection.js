/**
 * Database Connection Test Script
 * 
 * Run this to verify your database connection works before deploying
 * Usage: node test-connection.js
 */

require('dotenv').config();
const mysql = require('mysql2/promise');

const config = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'para_db',
  port: process.env.DB_PORT || 3306,
  connectTimeout: 20000
};

console.log('\n🔍 Testing Database Connection...\n');
console.log('Configuration:');
console.log(`  Host: ${config.host}`);
console.log(`  User: ${config.user}`);
console.log(`  Database: ${config.database}`);
console.log(`  Port: ${config.port}`);
console.log('\n⏳ Connecting...\n');

async function testConnection() {
  let connection;
  
  try {
    // Test connection
    connection = await mysql.createConnection(config);
    console.log('✅ Connection successful!\n');
    
    // Test database exists
    const [databases] = await connection.execute('SHOW DATABASES LIKE ?', [config.database]);
    if (databases.length === 0) {
      console.log('❌ Database not found!');
      console.log(`   Please create database: ${config.database}`);
      process.exit(1);
    }
    console.log('✅ Database exists!\n');
    
    // Test tables
    const [tables] = await connection.execute('SHOW TABLES');
    console.log('📋 Tables found:');
    if (tables.length === 0) {
      console.log('   ⚠️  No tables found. Run db.sql to create schema.');
    } else {
      tables.forEach(table => {
        const tableName = Object.values(table)[0];
        console.log(`   ✓ ${tableName}`);
      });
    }
    
    // Test users table structure
    const [users] = await connection.execute('SHOW TABLES LIKE "users"');
    if (users.length > 0) {
      const [columns] = await connection.execute('DESCRIBE users');
      console.log('\n👤 Users table structure:');
      columns.forEach(col => {
        console.log(`   ${col.Field}: ${col.Type}${col.Null === 'NO' ? ' NOT NULL' : ''}`);
      });
      
      // Count users
      const [countResult] = await connection.execute('SELECT COUNT(*) as count FROM users');
      console.log(`\n   Total users: ${countResult[0].count}`);
    }
    
    // Test messages table structure
    const [messages] = await connection.execute('SHOW TABLES LIKE "messages"');
    if (messages.length > 0) {
      const [columns] = await connection.execute('DESCRIBE messages');
      console.log('\n💬 Messages table structure:');
      columns.forEach(col => {
        console.log(`   ${col.Field}: ${col.Type}${col.Null === 'NO' ? ' NOT NULL' : ''}`);
      });
      
      // Count messages
      const [countResult] = await connection.execute('SELECT COUNT(*) as count FROM messages');
      console.log(`\n   Total messages: ${countResult[0].count}`);
    }
    
    console.log('\n✅ All checks passed! Database is ready.\n');
    
  } catch (error) {
    console.error('\n❌ Connection failed!\n');
    console.error('Error details:');
    console.error(`  Code: ${error.code}`);
    console.error(`  Message: ${error.message}`);
    
    if (error.code === 'ECONNREFUSED') {
      console.error('\n💡 Troubleshooting:');
      console.error('  - Is MySQL server running?');
      console.error('  - Is the host and port correct?');
      console.error('  - Check firewall settings');
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.error('\n💡 Troubleshooting:');
      console.error('  - Check username and password');
      console.error('  - Verify user has access to the database');
      console.error('  - For remote DB, check if IP is whitelisted');
    } else if (error.code === 'ENOTFOUND') {
      console.error('\n💡 Troubleshooting:');
      console.error('  - Check if hostname is correct');
      console.error('  - Verify internet connection');
      console.error('  - Try using IP address instead of hostname');
    }
    
    process.exit(1);
  } finally {
    if (connection) {
      await connection.end();
    }
  }
}

testConnection();
