import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { SignJWT } from 'jose';
import dotenv from 'dotenv';
import { Admin } from './admin.model';
import { User } from './user.model';

dotenv.config();
dotenv.config({ path: '../../.env' });

const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:3000')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const app = express();
app.use(cors({ origin: allowedOrigins }));
app.use(express.json());

const PORT = process.env.PORT || 5001;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/ecommerce';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// Shared password policy for admin & user registration
function validatePassword(password: unknown): string | null {
  if (typeof password !== 'string' || password.length < 8) {
    return 'Password must be at least 8 characters';
  }
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
    return 'Password must contain at least one letter and one number';
  }
  return null;
}

// Connect to MongoDB & Auto-Seed Default Admin
mongoose.connect(MONGODB_URI)
  .then(async () => {
    console.log('Auth service connected to MongoDB');
    try {
      const count = await Admin.countDocuments();
      if (count === 0) {
        console.log('🌱 No admin accounts found. Seeding default admin user...');
        const adminEmail = process.env.ADMIN_EMAIL || 'admin@ejadastore.com';
        const adminPassword = process.env.ADMIN_PASSWORD || 'secure_admin_password_123';

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(adminPassword, salt);

        const admin = new Admin({
          name: 'Super Admin',
          email: adminEmail,
          passwordHash: passwordHash,
        });
        await admin.save();
        console.log(`✅ Default admin account seeded successfully: ${adminEmail}`);
      }
    } catch (err) {
      console.error('❌ Failed to run automatic admin seeding:', err);
    }
  })
  .catch((err) => console.error('Auth service MongoDB connection error:', err));

// Admin Registration
app.post('/auth/admin/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ success: false, error: 'Email, password, and name are required' });
    }

    const pwError = validatePassword(password);
    if (pwError) {
      return res.status(400).json({ success: false, error: pwError });
    }

    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({ success: false, error: 'Admin already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const admin = new Admin({
      email,
      passwordHash,
      name,
    });
    await admin.save();

    return res.status(201).json({
      success: true,
      message: 'Admin created successfully',
      admin: {
        id: admin._id,
        email: admin.email,
        name: admin.name,
      }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Admin Login
app.post('/auth/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required' });
    }

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, admin.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    // Generate JWT token using jose
    const secret = new TextEncoder().encode(JWT_SECRET);
    const token = await new SignJWT({ id: admin._id.toString(), email: admin.email })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1d')
      .sign(secret);

    return res.status(200).json({
      success: true,
      message: 'Logged in successfully',
      token,
      admin: {
        id: admin._id,
        email: admin.email,
        name: admin.name,
      }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// User Registration
app.post('/auth/user/register', async (req, res) => {
  try {
    const { email, password, name, address } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ success: false, error: 'Email, password, and name are required' });
    }

    const pwError = validatePassword(password);
    if (pwError) {
      return res.status(400).json({ success: false, error: pwError });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
      email,
      passwordHash,
      name,
      address,
    });
    await user.save();

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
      }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// User Login
app.post('/auth/user/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    // Issue a JWT so the frontend can persist the user session (same scheme as admin login)
    const secret = new TextEncoder().encode(JWT_SECRET);
    const token = await new SignJWT({ id: user._id.toString(), email: user.email, role: 'user' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1d')
      .sign(secret);

    return res.status(200).json({
      success: true,
      message: 'Logged in successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        address: user.address,
      }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Auth service running on port ${PORT}`);
});
