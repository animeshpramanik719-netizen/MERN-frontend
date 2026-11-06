const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const crypto   = require('crypto');
const User     = require('../models/User');
const auth     = require('../middleware/auth');
const { sendOtpEmail, sendResetOtpEmail } = require('../utils/mailer');

/** Generate a 6-digit numeric OTP */
function generateOtp() {
  return String(crypto.randomInt(100000, 999999));
}

// ─────────────────────────────────────────────
// POST /api/auth/register
// Creates an unverified user and emails an OTP
// ─────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    // Check for existing VERIFIED user with same email
    const existing = await User.findOne({ email });
    if (existing && existing.isVerified) {
      return res.status(400).json({ msg: 'Email already registered.' });
    }

    const otp          = generateOtp();
    const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min

    if (existing) {
      // Resend / overwrite stale unverified record
      existing.username     = username;
      existing.password     = password;   // pre-save hook will hash
      existing.otp          = otp;
      existing.otpExpiresAt = otpExpiresAt;
      await existing.save();
    } else {
      const user = new User({ username, email, password, otp, otpExpiresAt });
      await user.save();
    }

    await sendOtpEmail(email, otp);

    return res.json({ msg: 'OTP sent to your email. Please verify.' });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// POST /api/auth/verify-otp
// Verifies OTP and activates the account
// ─────────────────────────────────────────────
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: 'User not found.' });
    }
    if (user.isVerified) {
      return res.status(400).json({ msg: 'Account already verified.' });
    }
    if (!user.otp || user.otp !== otp) {
      return res.status(400).json({ msg: 'Invalid OTP.' });
    }
    if (user.otpExpiresAt < new Date()) {
      return res.status(400).json({ msg: 'OTP has expired. Please register again.' });
    }

    // Activate account
    user.isVerified   = true;
    user.otp          = undefined;
    user.otpExpiresAt = undefined;
    await user.save();

    const payload = { user: { id: user.id } };
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5h' }, (err, token) => {
      if (err) throw err;
      res.json({
        token,
        user: {
          id:             user.id,
          username:       user.username,
          email:          user.email,
          profilePicture: user.profilePicture || '',
          coverImage:     user.coverImage || '',
          bio:            user.bio || '',
        },
      });
    });
  } catch (err) {
    console.error('Verify OTP error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// POST /api/auth/resend-otp
// Resends OTP for unverified account
// ─────────────────────────────────────────────
router.post('/resend-otp', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'User not found.' });
    if (user.isVerified) return res.status(400).json({ msg: 'Account already verified.' });

    const otp          = generateOtp();
    const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
    user.otp           = otp;
    user.otpExpiresAt  = otpExpiresAt;
    await user.save();

    await sendOtpEmail(email, otp);
    res.json({ msg: 'New OTP sent.' });
  } catch (err) {
    console.error('Resend OTP error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// POST /api/auth/login
// ─────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials.' });

    if (!user.isVerified) {
      return res.status(403).json({ msg: 'Please verify your email before logging in.', needsVerification: true, email });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials.' });

    const payload = { user: { id: user.id } };
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5h' }, (err, token) => {
      if (err) throw err;
      res.json({
        token,
        user: {
          id:             user.id,
          username:       user.username,
          email:          user.email,
          profilePicture: user.profilePicture || '',
          coverImage:     user.coverImage || '',
          bio:            user.bio || '',
        },
      });
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// POST /api/auth/forgot-password
// Generates a 6-digit OTP and sends it via email
// ─────────────────────────────────────────────
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    if (!email) {
      return res.status(400).json({ msg: 'Please enter your email address.' });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ msg: 'No account found with this email address.' });
    }

    const otp = generateOtp();
    const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    user.otp = otp;
    user.otpExpiresAt = otpExpiresAt;
    await user.save();

    console.log(`[AUTH FORGOT PASSWORD] Generated OTP for ${email}: ${otp}`);

    try {
      await sendResetOtpEmail(email, otp);
    } catch (mailErr) {
      console.warn('Mail send failed (continuing):', mailErr.message);
    }

    res.json({ msg: 'Password reset code sent to your email.' });
  } catch (err) {
    console.error('Forgot password error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// POST /api/auth/reset-password
// Verifies OTP and resets user password, returns auth token
// ─────────────────────────────────────────────
router.post('/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ msg: 'Please provide email, verification code, and new password.' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ msg: 'User not found.' });
    }

    if (!user.otp || user.otp !== otp) {
      return res.status(400).json({ msg: 'Invalid verification code.' });
    }

    if (user.otpExpiresAt && user.otpExpiresAt < new Date()) {
      return res.status(400).json({ msg: 'Verification code has expired. Please request a new one.' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ msg: 'New password must be at least 6 characters.' });
    }

    // Set new password (pre-save hook hashes it)
    user.password = newPassword;
    user.isVerified = true;
    user.otp = undefined;
    user.otpExpiresAt = undefined;
    await user.save();

    console.log(`[AUTH RESET PASSWORD] Password successfully reset for ${email}`);

    const payload = { user: { id: user.id } };
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5h' }, (err, token) => {
      if (err) throw err;
      res.json({
        msg: 'Password updated successfully!',
        token,
        user: {
          id:             user.id,
          username:       user.username,
          email:          user.email,
          profilePicture: user.profilePicture || '',
          coverImage:     user.coverImage || '',
          bio:            user.bio || '',
        },
      });
    });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// GET /api/auth/me
// ─────────────────────────────────────────────
router.get('/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -otp -otpExpiresAt');
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// ─────────────────────────────────────────────
// PUT /api/auth/profile
// Update username, bio, and/or profile picture
// ─────────────────────────────────────────────
const multer = require('multer');
const path   = require('path');
const fs     = require('fs');

const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, '../uploads/avatars');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `avatar_${req.user.id}_${Date.now()}${path.extname(file.originalname)}`);
  },
});
const uploadAvatar = multer({
  storage: avatarStorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only image files are allowed'));
  },
});

router.put('/profile', auth, uploadAvatar.single('profilePicture'), async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ msg: 'User not found' });

    const { username, bio, currentPassword, newPassword } = req.body;

    // Update username
    if (username && username.trim() !== user.username) {
      const taken = await User.findOne({ username: username.trim() });
      if (taken) return res.status(400).json({ msg: 'Username already taken.' });
      user.username = username.trim();
    }

    // Update bio
    if (bio !== undefined) user.bio = bio;

    // Update password
    if (newPassword) {
      if (!currentPassword) return res.status(400).json({ msg: 'Current password required to set a new one.' });
      const bcrypt = require('bcryptjs');
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) return res.status(400).json({ msg: 'Current password is incorrect.' });
      if (newPassword.length < 6) return res.status(400).json({ msg: 'New password must be at least 6 characters.' });
      user.password = newPassword; // pre-save hook will hash it
    }

    // Update profile picture
    if (req.file) {
      // Delete old avatar if exists
      if (user.profilePicture) {
        const cleanPath = user.profilePicture
          .replace('https://photo-gallery-1-d5n0.onrender.com', '')
          .replace('http://localhost:5000', '')
          .replace(/^https?:\/\/[^/]+/, '');
        const oldPath = path.join(__dirname, '..', cleanPath);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
      }
      user.profilePicture = `/uploads/avatars/${req.file.filename}`;
    }

    await user.save();

    res.json({
      id:             user._id,
      username:       user.username,
      email:          user.email,
      bio:            user.bio,
      profilePicture: user.profilePicture,
      coverImage:     user.coverImage,
    });
  } catch (err) {
    console.error('Profile update error:', err.message);
    res.status(500).json({ msg: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// PUT /api/auth/cover
// Upload custom profile banner/cover picture
// ─────────────────────────────────────────────
const coverStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, '../uploads/covers');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `cover_${req.user.id}_${Date.now()}${path.extname(file.originalname)}`);
  },
});

const uploadCover = multer({
  storage: coverStorage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB limit for high-res banner
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only image files are allowed'));
  },
});

router.put('/cover', auth, uploadCover.single('coverImage'), async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ msg: 'User not found' });

    if (req.file) {
      if (user.coverImage) {
        const oldPath = path.join(__dirname, '..', user.coverImage.replace(/^https?:\/\/[^\/]+/, ''));
        if (fs.existsSync(oldPath)) {
          try { fs.unlinkSync(oldPath); } catch (e) { /* ignore cleanup error */ }
        }
      }
      user.coverImage = `/uploads/covers/${req.file.filename}`;
      await user.save();
    }

    res.json({
      id:             user._id,
      username:       user.username,
      email:          user.email,
      bio:            user.bio,
      profilePicture: user.profilePicture,
      coverImage:     user.coverImage,
    });
  } catch (err) {
    console.error('Cover update error:', err.message);
    res.status(500).json({ msg: 'Server error updating cover image' });
  }
});

// ─────────────────────────────────────────────
// DELETE /api/auth/cover
// Remove custom profile banner
// ─────────────────────────────────────────────
router.delete('/cover', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ msg: 'User not found' });

    if (user.coverImage) {
      const oldPath = path.join(__dirname, '..', user.coverImage.replace(/^https?:\/\/[^\/]+/, ''));
      if (fs.existsSync(oldPath)) {
        try { fs.unlinkSync(oldPath); } catch (e) { /* ignore cleanup error */ }
      }
      user.coverImage = '';
      await user.save();
    }

    res.json({
      id:             user._id,
      username:       user.username,
      email:          user.email,
      bio:            user.bio,
      profilePicture: user.profilePicture,
      coverImage:     '',
    });
  } catch (err) {
    console.error('Cover delete error:', err.message);
    res.status(500).json({ msg: 'Server error deleting cover image' });
  }
});

module.exports = router;
