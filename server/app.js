const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const multer = require('multer');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

const app = express();
const JWT_SECRET = 'super-secret-key';
const GATEWAY_SECRET = 'gateway-secret-key';
const DB_PATH = '/app/data/db.txt';
const FILES_DB_PATH = '/app/data/files.json';
const ADMIN_TOKEN_PATH = '/app/data/token.json';
const ADMIN_SECRET_PATH = '/app/data/admin_2fa.json';

const uploadStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
        const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
        cb(null, Date.now() + '-' + originalName);
    }
});

const upload = multer({ 
    storage: uploadStorage,
    limits: { fileSize: 100 * 1024 },
    fileFilter: (req, file, cb) => {
        const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
        if (originalName.endsWith('.bsh')) cb(null, true);
        else cb(new Error('仅允许上传 .bsh 后缀的文件'));
    }
});

// 初始化管理员 Token
if (!fs.existsSync(ADMIN_TOKEN_PATH)) {
    const adminToken = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(ADMIN_TOKEN_PATH, JSON.stringify({ key: adminToken }, null, 2));
}

app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// 中间件定义
const adminOnly = (req, res, next) => {
    const token = req.cookies.admin_token;
    if (!token) return res.status(403).send({ message: '需要管理员权限' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === 'admin') return next();
        res.status(403).send({ message: '非管理员' });
    } catch(e) { res.status(403).send({ message: '验证失效' }); }
};

const gatewayAuth = (req, res, next) => {
    const token = req.cookies.gateway_token;
    if (!token) return res.status(403).send({ message: '请先完成人机验证', needsGateway: true });
    try {
        jwt.verify(token, GATEWAY_SECRET);
        next();
    } catch (e) { res.status(403).send({ message: '验证过期，请重新验证', needsGateway: true }); }
};

const userStatusCheck = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return next();
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const users = loadUsers();
        const user = users.find(u => u.username === decoded.username);
        if (!user || user.isBanned) {
            res.clearCookie('token');
            return res.status(403).send({ message: '账号不可用或已被封禁' });
        }
        req.currentUser = decoded.username;
        next();
    } catch (e) { res.clearCookie('token'); next(); }
};

app.use(userStatusCheck);

async function verifyTurnstile(token) {
    try {
        const res = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            secret: '0x4AAAAAADHW2HP8XJXbvAiaNpbLbXCZiaA',
            response: token
        });
        return res.data.success;
    } catch (e) { return false; }
}

// 辅助函数
function loadUsers() {
    try {
        if (!fs.existsSync(DB_PATH)) return [];
        const data = fs.readFileSync(DB_PATH, 'utf8').trim();
        return data ? JSON.parse(data) : [];
    } catch (e) { return []; }
}
function saveUsers(users) { fs.writeFileSync(DB_PATH, JSON.stringify(users, null, 2)); }
function loadFilesInfo() {
    try {
        if (!fs.existsSync(FILES_DB_PATH)) return [];
        const data = fs.readFileSync(FILES_DB_PATH, 'utf8').trim();
        return data ? JSON.parse(data) : [];
    } catch (e) { return []; }
}
function saveFilesInfo(files) { fs.writeFileSync(FILES_DB_PATH, JSON.stringify(files, null, 2)); }

// 路由
app.post('/api/verify-gateway', async (req, res) => {
    if (await verifyTurnstile(req.body.turnstileToken)) {
        const token = jwt.sign({ verified: true }, GATEWAY_SECRET, { expiresIn: '24h' });
        res.cookie('gateway_token', token, { httpOnly: true, path: '/' });
        return res.send({ message: '验证成功' });
    }
    res.status(403).send({ message: '验证失败' });
});

app.use('/api', (req, res, next) => {
    if (req.path === '/verify-gateway' || req.path.startsWith('/admin/login')) return next();
    gatewayAuth(req, res, next);
});

app.get('/api/resources', (req, res) => {
    const filesInfo = loadFilesInfo();
    fs.readdir(path.join(__dirname, '../uploads'), (err, files) => {
        if (err) return res.status(500).send({ message: '读取资源失败' });
        res.send({ resources: files.map(f => ({ filename: f, owner: (filesInfo.find(fi => fi.filename === f) || {}).owner || '未知' })) });
    });
});

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    let users = loadUsers();
    if (users.find(u => u.username === username)) return res.status(400).send({ message: '用户已存在' });
    users.push({ username, password: await bcrypt.hash(password, 10), isBanned: false });
    saveUsers(users);
    res.status(201).send({ message: '注册成功' });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    let users = loadUsers();
    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).send({ message: '用户名或密码错误' });
    if (user.isBanned) return res.status(403).send({ message: '您的账号已被封禁' });
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true, path: '/' });
    res.send({ message: '登录成功' });
});

app.get('/api/me', (req, res) => {
    if (!req.currentUser) return res.status(401).send({ message: '未登录' });
    res.send({ username: req.currentUser });
});

app.post('/api/upload', (req, res) => {
    upload.single('file')(req, res, (err) => {
        if (!req.currentUser) return res.status(401).send({ message: '请先登录' });
        if (err) return res.status(400).send({ message: err.code === 'LIMIT_FILE_SIZE' ? '大小限制 100KB' : err.message });
        if (!req.file) return res.status(400).send({ message: '未找到文件' });
        const filesInfo = loadFilesInfo();
        filesInfo.push({ filename: req.file.filename, owner: req.currentUser });
        saveFilesInfo(filesInfo);
        res.send({ message: '文件上传成功' });
    });
});

app.post('/api/admin/login', async (req, res) => {
    const { key, otpToken } = req.body;
    const savedToken = JSON.parse(fs.readFileSync(ADMIN_TOKEN_PATH, 'utf8')).key;
    if (key === savedToken || (fs.existsSync(ADMIN_SECRET_PATH) && speakeasy.totp.verify({ secret: JSON.parse(fs.readFileSync(ADMIN_SECRET_PATH, 'utf8')).base32, encoding: 'base32', token: otpToken }))) {
        res.cookie('admin_token', jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '2h' }), { httpOnly: true, path: '/' });
        return res.send({ message: '管理员登录成功' });
    }
    res.status(401).send({ message: '验证失败' });
});

app.get('/api/admin/setup-2fa', adminOnly, (req, res) => {
    const secret = speakeasy.generateSecret({ name: 'Resource Depot Admin' });
    fs.writeFileSync(ADMIN_SECRET_PATH, JSON.stringify(secret));
    qrcode.toDataURL(secret.otpauth_url, (err, url) => res.send({ qrCode: url, secret: secret.base32 }));
});

app.get('/api/admin/files', adminOnly, (req, res) => res.send({ files: loadFilesInfo() }));
app.get('/api/admin/users', adminOnly, (req, res) => res.send({ users: loadUsers().map(u => ({ username: u.username, isBanned: u.isBanned })) }));
app.post('/api/admin/toggle-ban/:username', adminOnly, (req, res) => {
    let users = loadUsers();
    const idx = users.findIndex(u => u.username === req.params.username);
    if (idx === -1) return res.status(404).send({ message: '未找到用户' });
    users[idx].isBanned = !users[idx].isBanned;
    saveUsers(users);
    res.send({ message: users[idx].isBanned ? '已封禁' : '已解封' });
});
app.delete('/api/admin/user/:username', adminOnly, (req, res) => {
    saveUsers(loadUsers().filter(u => u.username !== req.params.username));
    res.send({ message: '用户已注销' });
});

app.delete('/api/delete/:filename', (req, res) => {
    const adminToken = req.cookies.admin_token;
    let isAdmin = false;
    try { if (adminToken && jwt.verify(adminToken, JWT_SECRET).role === 'admin') isAdmin = true; } catch(e) {}
    if (!isAdmin && !req.currentUser) return res.status(401).send({ message: '请先登录' });
    
    const filesInfo = loadFilesInfo();
    const fileRecord = filesInfo.find(f => f.filename === req.params.filename);
    if (!fileRecord) return res.status(404).send({ message: '文件记录不存在' });
    if (!isAdmin && fileRecord.owner !== req.currentUser) return res.status(403).send({ message: '无权限' });
    
    const filePath = path.join(__dirname, '../uploads', req.params.filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    saveFilesInfo(filesInfo.filter(f => f.filename !== req.params.filename));
    res.send({ message: '文件已删除' });
});

app.listen(3000, () => console.log('服务器运行在 http://localhost:3000'));
