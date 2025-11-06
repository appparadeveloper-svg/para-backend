# PARA Backend Server

## Features

- ✅ UUID-based user IDs (BINARY format with UUID_TO_BIN)
- ✅ AES encryption for sensitive fields (full_name, email)
- ✅ Account locking after failed login attempts
- ✅ JWT authentication
- ✅ Chat message persistence

## Setup

1. Install dependencies:
```bash
npm install
```

2. Configure environment variables:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your configuration (see Environment Variables section)

3. Set up MySQL database:
   - Create a MySQL database
   - Import the schema:
     ```bash
     mysql -u root -p para_db < db.sql
     ```

4. Start the server:
   ```bash
   # Development mode (with auto-reload)
   npm run dev

   # Production mode
   npm start
   ```

## Environment Variables

Create a `.env` file with the following variables:

```env
# Database Configuration
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=para_db
DB_PORT=3306

# Security Keys (generate new ones for production!)
JWT_SECRET=your_jwt_secret_here
ENCRYPTION_KEY=your_encryption_key_here

# Server Configuration
PORT=3000
NODE_ENV=development

# Cloudinary Configuration (for avatar uploads)
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
```

## Deployment to Production

### Quick Deploy to Render

1. **Push code to GitHub**
2. **Create Render account** and link repository
3. **Set environment variables** in Render dashboard
4. **Deploy!**

📖 **See [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md) for complete step-by-step instructions**

The deployment guide includes:
- Hostinger MySQL database setup
- Render backend deployment
- Flutter app configuration
- Testing procedures
- Troubleshooting tips

## Database Schema

### Users Table
- `id`: BINARY(16) - UUID in binary format
- `full_name`: VARBINARY(255) - Encrypted with AES
- `email`: VARBINARY(255) - Encrypted with AES
- `password_hash`: VARCHAR(255) - bcrypt hashed password
- `is_locked`: TINYINT(1) - Account lock status
- `failed_login_attempts`: INT - Counter for failed attempts
- `locked_until`: DATETIME - When lock expires
- `last_login_attempt`: DATETIME - Last attempt timestamp

### Messages Table
- `id`: BIGINT UNSIGNED - Auto increment
- `user_id`: BINARY(16) - Foreign key to users (UUID)
- `text`: TEXT - Message content
- `is_bot`: TINYINT(1) - Bot/user flag
- `timestamp`: DATETIME - Message timestamp
- `error`: TEXT - Optional error info

## Security Features

### Account Locking
- After 5 failed login attempts, account is locked for 30 minutes
- Lock automatically expires after the timeout period
- Failed attempts are reset on successful login

### Data Encryption
- Email and full name are encrypted using AES-256
- Encryption key is derived from ENCRYPTION_KEY using SHA-256
- Data is automatically decrypted when retrieved

### UUID Implementation
- User IDs use UUID v4 format stored as BINARY(16)
- More secure than sequential IDs
- Better for distributed systems

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user

### Chat Messages
- `GET /api/chats/:userId/messages` - Get messages for user
- `POST /api/chats/:userId/messages` - Save new message
- `DELETE /api/chats/:userId/messages` - Delete all messages for user

## Migration from INT to UUID

```bash
npm run dev
```

### Testing
```bash
# Test registration
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"fullName":"Test","email":"test@test.com","password":"test123"}'

# Test login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123"}'
```

## Troubleshooting

### Database Connection Issues
- Verify MySQL is running
- Check credentials in `.env`
- Ensure database exists
- Check firewall settings

### Authentication Errors
- Verify JWT_SECRET is set
- Check token format (Bearer <token>)
- Ensure token hasn't expired

### CORS Errors
- Backend has CORS enabled by default
- For production, update CORS config in `server.js`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is private and not licensed for public use.

## Support

For deployment help, see [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md)

For issues, check the troubleshooting section or contact the development team.
