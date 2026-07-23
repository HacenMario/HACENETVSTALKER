require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// CORS - السماح لجميع النطاقات (للاختبار)
app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        const allowed = [
            'https://hacene-tv-stalker.vercel.app',
            'http://localhost:3000',
            'http://localhost:5500',
            'https://hacenetv2-0.onrender.com'
        ];
        const clean = origin.replace(/\/$/, '');
        if (allowed.includes(clean) || allowed.includes(origin)) {
            callback(null, true);
        } else {
            callback(null, true);
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// ===== MongoDB Connection =====
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
    console.error('❌ MONGODB_URI not defined');
    process.exit(1);
}

mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
    });

// ===== Schemas =====
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], default: 'user' },
    isActive: { type: Boolean, default: true },
    stalker: {
        server: { type: String, default: '' },
        mac: { type: String, default: '' },
        deviceId: { type: String, default: '' },
        serial: { type: String, default: '' }
    },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

const ChannelSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    channels: { type: Array, default: [] },
    updatedAt: { type: Date, default: Date.now }
});

const Channel = mongoose.model('Channel', ChannelSchema);

const NotificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    message: { type: String, required: true },
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const Notification = mongoose.model('Notification', NotificationSchema);

// ===== Helpers =====
function generateToken(userId, email, role) {
    return jwt.sign(
        { userId, email, role },
        process.env.JWT_SECRET || 'hacene_tv_secret_key_2025',
        { expiresIn: '30d' }
    );
}

function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'hacene_tv_secret_key_2025');
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

function adminMiddleware(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin required' });
    }
    next();
}

// ===== STALKER Helpers =====
async function authenticateStalker(portalUrl, mac, deviceId = '', serial = '') {
    try {
        // طلب المصادقة الأولي (device)
        const deviceRes = await fetch(`${portalUrl}/stb/device`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                mac: mac,
                device_id: deviceId || 'any',
                serial: serial || 'any'
            })
        });

        if (!deviceRes.ok) {
            throw new Error(`HTTP ${deviceRes.status} - ${deviceRes.statusText}`);
        }

        const deviceData = await deviceRes.json();
        if (!deviceData.token) {
            throw new Error('Stalker authentication failed: no token received');
        }

        return deviceData.token;
    } catch (err) {
        console.error('Stalker auth error:', err);
        throw new Error('Stalker authentication failed: ' + err.message);
    }
}

async function fetchStalkerChannels(portalUrl, mac, deviceId = '', serial = '') {
    // 1. المصادقة والحصول على token
    const token = await authenticateStalker(portalUrl, mac, deviceId, serial);

    // 2. جلب القنوات
    const channelsRes = await fetch(`${portalUrl}/get_all_channels`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!channelsRes.ok) {
        throw new Error(`Failed to fetch channels: ${channelsRes.status}`);
    }

    const channelsData = await channelsRes.json();
    if (!Array.isArray(channelsData)) {
        throw new Error('Invalid response from Stalker server');
    }

    // 3. تحويل البيانات إلى صيغة موحدة مع إضافة الرابط المؤقت
    return channelsData.map(ch => ({
        name: ch.name || ch.channel_name || 'بدون اسم',
        category: ch.category_name || 'عام',
        stream_id: ch.id || ch.channel_id || ch.stream_id,
        icon: ch.logo || ch.stream_icon || '',
        url: `${portalUrl}/media/${token}/${ch.id || ch.channel_id || ch.stream_id}.m3u8`,
        _token: token  // للتجديد لاحقاً
    }));
}

// ===== Auth endpoints =====
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
        if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });

        const existing = await User.findOne({ email: email.toLowerCase() });
        if (existing) return res.status(400).json({ error: 'Email already registered' });

        const hashed = await bcrypt.hash(password, 10);
        const count = await User.countDocuments();
        const role = count === 0 ? 'admin' : 'user';

        const user = new User({
            email: email.toLowerCase(),
            password: hashed,
            role: role,
            isActive: true,
            stalker: { server: '', mac: '', deviceId: '', serial: '' }
        });
        await user.save();

        const token = generateToken(user._id, user.email, user.role);
        res.status(201).json({
            success: true,
            token,
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                isActive: user.isActive,
                stalker: user.stalker
            }
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Server error: ' + err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(401).json({ error: 'Invalid email or password' });

        if (!user.isActive) return res.status(403).json({ error: 'Account disabled' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

        const token = generateToken(user._id, user.email, user.role);
        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                isActive: user.isActive,
                stalker: user.stalker
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error: ' + err.message });
    }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ user });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== User Stalker & Channels =====
app.post('/api/user/stalker', authMiddleware, async (req, res) => {
    try {
        const { server, mac, deviceId, serial } = req.body;
        if (!server || !mac) {
            return res.status(400).json({ error: 'Portal URL and MAC required' });
        }

        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        // حفظ إعدادات Stalker
        user.stalker = { server, mac, deviceId: deviceId || '', serial: serial || '' };
        await user.save();

        // جلب القنوات
        const channels = await fetchStalkerChannels(server, mac, deviceId, serial);

        // حفظ القنوات في قاعدة البيانات
        await Channel.findOneAndUpdate(
            { userId: user._id },
            { userId: user._id, channels, updatedAt: Date.now() },
            { upsert: true, new: true }
        );

        res.json({ success: true, channels, count: channels.length });
    } catch (err) {
        console.error('Stalker fetch error:', err);
        res.status(500).json({ error: err.message });
    }
});

// نقطة نهاية لاختبار الاتصال دون حفظ
app.post('/api/user/stalker-test', authMiddleware, async (req, res) => {
    try {
        const { server, mac, deviceId, serial } = req.body;
        if (!server || !mac) {
            return res.status(400).json({ error: 'Portal URL and MAC required' });
        }

        // محاولة المصادقة فقط
        const token = await authenticateStalker(server, mac, deviceId, serial);
        res.json({ success: true, message: 'الاتصال ناجح، تم الحصول على token' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// الحصول على رابط تشغيل مع تجديد token إذا لزم الأمر
app.post('/api/user/stalker-link', authMiddleware, async (req, res) => {
    try {
        const { stream_id } = req.body;
        if (!stream_id) return res.status(400).json({ error: 'stream_id required' });

        const user = await User.findById(req.user.userId);
        if (!user || !user.stalker || !user.stalker.server || !user.stalker.mac) {
            return res.status(400).json({ error: 'Stalker not configured' });
        }

        const { server, mac, deviceId, serial } = user.stalker;
        // تجديد المصادقة للحصول على token جديد
        const token = await authenticateStalker(server, mac, deviceId, serial);
        const url = `${server}/media/${token}/${stream_id}.m3u8`;

        // تحديث الروابط المخزنة للقنوات (اختياري)
        const channelDoc = await Channel.findOne({ userId: user._id });
        if (channelDoc) {
            const updatedChannels = channelDoc.channels.map(ch => {
                if (ch.stream_id == stream_id) {
                    return { ...ch, url, _token: token };
                }
                return ch;
            });
            channelDoc.channels = updatedChannels;
            await channelDoc.save();
        }

        res.json({ success: true, url });
    } catch (err) {
        console.error('Stalker link error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/user/channels', authMiddleware, async (req, res) => {
    try {
        const doc = await Channel.findOne({ userId: req.user.userId });
        res.json({ channels: doc ? doc.channels : [] });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/user/channels', authMiddleware, async (req, res) => {
    try {
        const { channels } = req.body;
        if (!Array.isArray(channels)) return res.status(400).json({ error: 'Channels must be array' });
        await Channel.findOneAndUpdate(
            { userId: req.user.userId },
            { userId: req.user.userId, channels, updatedAt: Date.now() },
            { upsert: true, new: true }
        );
        res.json({ success: true, channels });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== Admin endpoints =====
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find({}).select('-password');
        res.json({ users });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/admin/users/:userId', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;
        const { isActive, stalker } = req.body;
        if (userId === req.user.userId) return res.status(403).json({ error: 'Cannot modify self' });

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        if (isActive !== undefined) user.isActive = isActive;
        if (stalker) {
            user.stalker = {
                server: stalker.server || '',
                mac: stalker.mac || '',
                deviceId: stalker.deviceId || '',
                serial: stalker.serial || ''
            };
        }
        await user.save();

        res.json({
            success: true,
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                isActive: user.isActive,
                stalker: user.stalker
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/api/admin/users/:userId', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;
        if (userId === req.user.userId) return res.status(403).json({ error: 'Cannot delete self' });
        await User.findByIdAndDelete(userId);
        await Channel.findOneAndDelete({ userId });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== Admin Notifications =====
app.post('/api/admin/notifications', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { message, targetEmail } = req.body;
        if (!message) return res.status(400).json({ error: 'Message is required' });

        let query = {};
        if (targetEmail) {
            const targetUser = await User.findOne({ email: targetEmail.toLowerCase() });
            if (!targetUser) return res.status(404).json({ error: 'User with that email not found' });
            query = { _id: targetUser._id };
        }

        const users = await User.find(query).select('_id');
        if (users.length === 0) return res.status(404).json({ error: 'No users found to notify' });

        const notifications = users.map(u => ({
            userId: u._id,
            message: message,
            read: false,
            createdAt: new Date()
        }));

        await Notification.insertMany(notifications);

        res.json({ success: true, count: notifications.length });
    } catch (err) {
        console.error('Notification error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== User Notifications =====
app.get('/api/user/notifications', authMiddleware, async (req, res) => {
    try {
        const notifs = await Notification.find({ userId: req.user.userId }).sort({ createdAt: -1 });
        res.json({ notifications: notifs });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/user/notifications/:id/read', authMiddleware, async (req, res) => {
    try {
        const notif = await Notification.findOne({ _id: req.params.id, userId: req.user.userId });
        if (!notif) return res.status(404).json({ error: 'Notification not found' });
        notif.read = true;
        await notif.save();
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== Proxy =====
app.get('/api/proxy', async (req, res) => {
    try {
        const target = req.query.url;
        if (!target) return res.status(400).json({ error: 'Missing url' });
        const response = await fetch(target);
        if (!response.ok) return res.status(response.status).json({ error: 'Fetch failed' });
        const data = await response.json();
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: 'Proxy error: ' + err.message });
    }
});

// ===== Health =====
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
