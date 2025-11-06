# Para Backend Deployment Guide

## Table of Contents
1. [Hostinger MySQL Setup](#hostinger-mysql-setup)
2. [Render Deployment](#render-deployment)
3. [Flutter App Configuration](#flutter-app-configuration)
4. [Testing the Connection](#testing-the-connection)
5. [Troubleshooting](#troubleshooting)

---

## Hostinger MySQL Setup

### Step 1: Create MySQL Database on Hostinger

1. **Log in to your Hostinger account**
   - Go to https://hpanel.hostinger.com/

2. **Navigate to Databases**
   - Click on "Websites" in the left menu
   - Select your hosting plan
   - Go to "Databases" → "MySQL Databases"

3. **Create a New Database**
   - Click "Create New Database"
   - Database name: `para_db` (or your preferred name)
   - Username: Create a new user with a strong password
   - Save the credentials securely

4. **Note Down Your Connection Details**
   You'll need these for Render deployment:
   ```
   DB_HOST: [Usually something like mysql.hostinger.com or specific IP]
   DB_USER: [Your database username]
   DB_PASSWORD: [Your database password]
   DB_NAME: para_db
   DB_PORT: 3306
   ```

5. **Enable Remote MySQL Access**
   - In Hostinger panel, go to "Remote MySQL"
   - Add the following IP address to whitelist: `0.0.0.0/0` (or Render's IP if available)
   - This allows your Render backend to connect to the database

### Step 2: Import Database Schema

1. **Access phpMyAdmin**
   - In Hostinger panel, click "Manage" next to your database
   - This opens phpMyAdmin

2. **Import the Schema**
   - Click on your database name in the left sidebar
   - Go to the "Import" tab
   - Upload the `db.sql` file from your backend folder
   - Click "Go" to execute

3. **Verify Tables**
   After import, you should see these tables:
   - `users`
   - `messages`

---

## Render Deployment

### Step 1: Prepare Your Repository

1. **Create a GitHub Repository**
   ```bash
   cd para-backend
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/yourusername/para-backend.git
   git push -u origin main
   ```

2. **Add .gitignore** (if not present)
   ```
   node_modules/
   .env
   .env.local
   .DS_Store
   ```

### Step 2: Deploy to Render

1. **Create Render Account**
   - Go to https://render.com/
   - Sign up with your GitHub account

2. **Create New Web Service**
   - Click "New +" → "Web Service"
   - Connect your GitHub repository (`para-backend`)
   - Configure the service:
     ```
     Name: para-backend (or your preferred name)
     Environment: Node
     Build Command: npm install
     Start Command: npm start
     Plan: Free
     ```

3. **Add Environment Variables**
   In Render Dashboard → Environment:
   
   ```
   NODE_ENV = production
   
   # Database Configuration (from Hostinger)
   DB_HOST = [Your Hostinger MySQL host]
   DB_USER = [Your database username]
   DB_PASSWORD = [Your database password]
   DB_NAME = para_db
   DB_PORT = 3306
   
   # Generate new secure keys for production
   JWT_SECRET = [Generate a random 64-character string]
   ENCRYPTION_KEY = [Generate a random 64-character string]
   
   # Cloudinary (for image uploads)
   CLOUDINARY_CLOUD_NAME = [Your Cloudinary cloud name]
   CLOUDINARY_API_KEY = [Your Cloudinary API key]
   CLOUDINARY_API_SECRET = [Your Cloudinary API secret]
   
   PORT = 10000
   ```

   **To generate secure keys:**
   ```bash
   # On Linux/Mac
   openssl rand -hex 32
   
   # Or use online generator: https://www.random.org/strings/
   ```

4. **Deploy**
   - Click "Create Web Service"
   - Render will automatically deploy your app
   - Wait for the build to complete (5-10 minutes)

5. **Note Your Backend URL**
   After deployment, you'll get a URL like:
   ```
   https://para-backend-xxxx.onrender.com
   ```

---

## Flutter App Configuration

### Step 1: Update API Configuration

1. **Open the API config file:**
   ```dart
   // lib/config/api_config.dart
   ```

2. **Update the production URL:**
   ```dart
   static const String _productionUrl = 'https://your-app-name.onrender.com/api';
   ```
   Replace `your-app-name` with your actual Render app name.

3. **Switch to Production Mode:**
   When ready to deploy your Flutter app:
   ```dart
   static const bool isProduction = true;
   ```

### Step 2: Test Locally First

Before switching to production:
1. Keep `isProduction = false`
2. Test your app with local backend
3. Once satisfied, switch to production

### Step 3: Build and Deploy Flutter App

**For Android:**
```bash
cd para
flutter build apk --release
```

**For iOS:**
```bash
flutter build ios --release
```

**For Web:**
```bash
flutter build web --release
```

---

## Testing the Connection

### Test Backend Endpoints

1. **Health Check:**
   ```bash
   curl https://your-app.onrender.com/
   ```

2. **Test Registration:**
   ```bash
   curl -X POST https://your-app.onrender.com/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{
       "fullName": "Test User",
       "email": "test@example.com",
       "password": "testpassword123"
     }'
   ```

3. **Test Login:**
   ```bash
   curl -X POST https://your-app.onrender.com/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{
       "email": "test@example.com",
       "password": "testpassword123"
     }'
   ```

### Monitor Logs

In Render Dashboard:
- Go to your service
- Click "Logs" tab
- Watch for any errors or connection issues

---

## Troubleshooting

### Issue: Database Connection Failed

**Solution:**
1. Verify Hostinger MySQL credentials are correct
2. Check if remote access is enabled in Hostinger
3. Ensure IP address `0.0.0.0/0` is whitelisted
4. Check Render logs for specific error messages

### Issue: CORS Errors

**Solution:**
The backend already has CORS enabled. If issues persist:
```javascript
// In server.js, update CORS configuration:
app.use(cors({
  origin: ['https://your-flutter-web-app.com'],
  credentials: true
}));
```

### Issue: Environment Variables Not Loading

**Solution:**
1. Double-check all environment variables in Render dashboard
2. Ensure no extra spaces in variable names or values
3. Redeploy after updating environment variables

### Issue: Render Free Tier Sleeps After Inactivity

**Solution:**
Render free tier apps sleep after 15 minutes of inactivity. Options:
1. Upgrade to paid plan ($7/month)
2. Use a service like UptimeRobot to ping your app every 5 minutes
3. Accept cold starts (first request may be slow)

### Issue: Migration Errors

**Solution:**
If you encounter UUID migration issues:
1. Access phpMyAdmin on Hostinger
2. Run the `migrate_to_uuid.sql` script
3. Verify all tables are using BINARY(16) for UUID columns

---

## Security Best Practices

1. **Never commit `.env` files to Git**
2. **Use strong, unique passwords** for database
3. **Regenerate JWT and encryption keys** for production
4. **Enable SSL/TLS** (Render provides this automatically)
5. **Regularly update dependencies:**
   ```bash
   npm audit fix
   npm update
   ```

6. **Monitor logs regularly** for suspicious activity
7. **Set up database backups** in Hostinger panel

---

## Maintenance

### Updating the Backend

1. Make changes locally
2. Test thoroughly
3. Commit and push to GitHub:
   ```bash
   git add .
   git commit -m "Your update message"
   git push origin main
   ```
4. Render will auto-deploy (if enabled)

### Database Backups

In Hostinger:
1. Go to phpMyAdmin
2. Select your database
3. Click "Export"
4. Choose format (SQL recommended)
5. Download and store securely

---

## Cost Breakdown

- **Hostinger MySQL Database:** Included with hosting plan (~$2-10/month)
- **Render Backend (Free Tier):** $0/month
  - 750 hours/month
  - Sleeps after inactivity
- **Render Backend (Starter):** $7/month
  - Always on
  - Better performance
- **Cloudinary (Free Tier):** $0/month
  - 25 GB storage
  - 25 GB bandwidth

---

## Support

If you encounter issues:
1. Check Render logs
2. Check Hostinger database connectivity
3. Review this guide's troubleshooting section
4. Contact Render support: https://render.com/docs
5. Contact Hostinger support: https://www.hostinger.com/contact

---

## Quick Reference

### Render Dashboard
https://dashboard.render.com/

### Hostinger Panel
https://hpanel.hostinger.com/

### Cloudinary Dashboard
https://cloudinary.com/console/

### Test Your Backend
```bash
# Replace with your actual URL
curl https://your-app.onrender.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123"}'
```

---

## Next Steps

1. ✅ Set up Hostinger MySQL database
2. ✅ Deploy backend to Render
3. ✅ Configure Flutter app with production URL
4. ✅ Test all endpoints
5. ✅ Build and release Flutter app
6. ✅ Monitor and maintain

Good luck with your deployment! 🚀
