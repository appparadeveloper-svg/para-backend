# Quick Start Guide - Para Backend Deployment

## 🚀 5-Minute Setup

### Step 1: Hostinger MySQL (5 min)
1. Go to https://hpanel.hostinger.com/
2. Databases → Create MySQL Database → `para_db`
3. Create user with strong password
4. Enable Remote MySQL → Whitelist `0.0.0.0/0`
5. Import `db.sql` via phpMyAdmin

**Save these credentials:**
```
DB_HOST: [mysql.hostinger.com or your host]
DB_USER: [your username]
DB_PASSWORD: [your password]
DB_NAME: para_db
```

### Step 2: Push to GitHub (2 min)
```bash
cd para-backend
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/yourusername/para-backend.git
git push -u origin main
```

### Step 3: Deploy to Render (3 min)
1. Go to https://render.com/ → Sign in with GitHub
2. New → Web Service → Connect `para-backend` repo
3. Settings:
   - **Name:** para-backend
   - **Build:** `npm install`
   - **Start:** `npm start`
4. Add Environment Variables (copy from below)
5. Create Web Service

**Environment Variables:**
```
NODE_ENV=production
DB_HOST=[from Step 1]
DB_USER=[from Step 1]
DB_PASSWORD=[from Step 1]
DB_NAME=para_db
DB_PORT=3306
JWT_SECRET=[generate with: openssl rand -hex 32]
ENCRYPTION_KEY=[generate with: openssl rand -hex 32]
CLOUDINARY_CLOUD_NAME=[your cloudinary name]
CLOUDINARY_API_KEY=[your cloudinary key]
CLOUDINARY_API_SECRET=[your cloudinary secret]
PORT=10000
```

### Step 4: Update Flutter App (1 min)
```dart
// lib/config/api_config.dart
static const String _productionUrl = 'https://your-app.onrender.com/api';
static const bool isProduction = true; // Change when ready for production
```

### Step 5: Test (2 min)
```bash
# Test backend is live
curl https://your-app.onrender.com/

# Test registration
curl -X POST https://your-app.onrender.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"fullName":"Test User","email":"test@example.com","password":"test123"}'
```

## ✅ You're Done!

Your backend is now:
- ✅ Running on Render
- ✅ Connected to Hostinger MySQL
- ✅ Ready for your Flutter app

**Your Backend URL:**
```
https://[your-app-name].onrender.com
```

## 📱 Next Steps

1. **Update Flutter app** with your backend URL
2. **Build your app:**
   ```bash
   flutter build apk --release  # Android
   flutter build ios --release  # iOS
   ```
3. **Test with real devices**

## 🆘 Having Issues?

### Backend won't start
- Check Render logs
- Verify all environment variables are set
- Ensure no typos in variable names

### Can't connect to database
- Verify Hostinger credentials
- Check if remote access is enabled
- Ensure IP `0.0.0.0/0` is whitelisted

### Flutter app can't connect
- Verify backend URL in `api_config.dart`
- Check if backend is running (visit URL in browser)
- Wait 30-60 seconds if backend was sleeping

## 📚 More Help

- **Full Guide:** [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md)
- **Checklist:** [../DEPLOYMENT_CHECKLIST.md](../DEPLOYMENT_CHECKLIST.md)
- **README:** [README.md](./README.md)

## 💡 Pro Tips

1. **Free Tier Sleeping:** Render free tier sleeps after 15 min inactivity
   - Use UptimeRobot to ping every 5 minutes
   - Or upgrade to $7/month Starter plan

2. **Database Backups:** Set up automated backups in Hostinger panel

3. **Monitoring:** Check Render logs regularly for errors

4. **Security:** Never commit `.env` file to Git!

---

**Total Time:** ~15 minutes
**Cost:** $0/month (with Render free tier + basic Hostinger hosting)

Need detailed instructions? See [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md)
