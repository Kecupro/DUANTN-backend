const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../model/User');
const bcrypt = require('bcrypt');
require('dotenv').config();

// Debug: Kiểm tra biến môi trường
console.log('=== DEBUG GOOGLE OAUTH ===');
console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID);
console.log('GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET);
console.log('GOOGLE_CLIENT_ID length:', process.env.GOOGLE_CLIENT_ID ? process.env.GOOGLE_CLIENT_ID.length : 'undefined');
console.log('=== END DEBUG ===');

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Kiểm tra user theo googleId trước
      let user = await User.findOne({ googleId: profile.id });
      
      if (!user) {
        // Nếu không tìm thấy theo googleId, kiểm tra theo email
        user = await User.findOne({ email: profile.emails[0].value });
        
        if (user) {
          // Nếu user đã tồn tại với email này, cập nhật thêm googleId
          user.googleId = profile.id;
          if (!user.fullname) user.fullname = profile.displayName;
          if (!user.avatar && profile.photos && profile.photos.length > 0) {
            user.avatar = profile.photos[0].value;
          }
          await user.save();
        } else {
          // Tạo user mới nếu chưa tồn tại
          const randomPassword = Math.random().toString(36).slice(-10) + Date.now().toString(36);
          const password_hash = await bcrypt.hash(randomPassword, 10);
          
        user = await User.create({
          googleId: profile.id,
          username: profile.emails[0].value,
          email: profile.emails[0].value,
          fullname: profile.displayName,
            password_hash: password_hash,
          account_status: '1',
          role: '0',
          avatar: profile.photos && profile.photos.length > 0 ? profile.photos[0].value : null
        });
      }
      }
      
      return done(null, user);
    } catch (err) {
      console.error('Google OAuth error:', err);
      return done(err, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});