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

const app = express();
const JWT_SECRET = 'super-secret-key';
const GATEWAY_SECRET = 'gateway-secret-key';
const DB_PATH = path.join(__dirname, 'db.txt');
const FILES_DB_PATH = path.join(__dirname, 'files.json');
const ADMIN_TOKEN_PATH = path.join(__dirname, 'token.json');
const ADMIN_SECRET_PATH = path.join(__dirname, 'admin_2fa.json');
const uploadStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
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
        if (originalName.endsWith('.bsh')) {
            cb(null, true);
        } else {
            cb(new Error('仅允许上传 .bsh 后缀的文件'));
        }
    }
});

// 初始化管理员 Token
if (!fs.existsSync(ADMIN_TOKEN_PATH)) {
    const adminToken = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(ADMIN_TOKEN_PATH, JSON.stringify({ key: adminToken }, null, 2));
    console.log('=============================================');
    console.log('--- 管理员首次启动密钥已生成 ---');
    console.log('密钥内容:', adminToken);
    console.log('文件保存于:', ADMIN_TOKEN_PATH);
    console.log('=============================================');
}
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 100 * 1024 }, // 限制 100KB
    fileFilter: (req, file, cb) => {
        const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
        if (originalName.endsWith('.bsh')) {
            cb(null, true);
        } else {
            cb(new Error('仅允许上传 .bsh 后缀的文件'));
        }
    }
});

app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

// 中间件：检查网关验证
const gatewayAuth = (req, res, next) => {
    const token = req.cookies.gateway_token;
    if (!token) {
        return res.status(403).send({ message: '请先完成人机验证', needsGateway: true });
    }
    try {
        jwt.verify(token, GATEWAY_SECRET);
        next();
    } catch (e) {
        res.status(403).send({ message: '验证过期，请重新验证', needsGateway: true });
    }
};

async function verifyTurnstile(token) {
    try {
        const res = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            secret: '0x4AAAAAADHW2HP8XJXbvAiaNpbLbXCZiaA',
            response: token
        });
        if (!res.data.success) {
            console.error('Turnstile 验证详情:', res.data);
        }
        return res.data.success;
    } catch (e) {
        console.error('Turnstile API 请求异常:', e.message);
        return false;
    }
}

// 网关验证接口
app.post('/api/verify-gateway', async (req, res) => {
    const { turnstileToken } = req.body;
    if (await verifyTurnstile(turnstileToken)) {
        const token = jwt.sign({ verified: true }, GATEWAY_SECRET, { expiresIn: '24h' });
        res.cookie('gateway_token', token, { httpOnly: true, path: '/' });
        return res.send({ message: '验证成功' });
    }
    res.status(403).send({ message: '验证失败' });
});

// 应用网关验证中间件到所有后续 API
app.use('/api', (req, res, next) => {
    if (req.path === '/verify-gateway') return next();
    gatewayAuth(req, res, next);
});

function loadUsers() {
    try {
        if (!fs.existsSync(DB_PATH)) return [];
        const data = fs.readFileSync(DB_PATH, 'utf8').trim();
        return data ? JSON.parse(data) : [];
    } catch (e) {
        console.error('数据库解析失败，重置为空数组:', e.message);
        return [];
    }
}

function saveUsers(users) {
    fs.writeFileSync(DB_PATH, JSON.stringify(users, null, 2));
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.get('/api/resources', (req, res) => {
    fs.readdir(path.join(__dirname, '../uploads'), (err, files) => {
        if (err) return res.status(500).send({ message: '读取资源失败' });
        res.send({ resources: files });
    });
});

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    let users = loadUsers();
    if (users.find(u => u.username === username)) {
        return res.status(400).send({ message: '用户已存在' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    saveUsers(users);
    res.status(201).send({ message: '注册成功' });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    let users = loadUsers();
    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send({ message: '用户名或密码错误' });
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true, path: '/' });
    res.send({ message: '登录成功' });
});

app.get('/api/me', (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).send({ message: '未登录' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.send({ username: decoded.username });
    } catch (e) {
        res.status(401).send({ message: '登录过期' });
    }
});

const FILES_DB_PATH = path.join(__dirname, 'files.json');

function loadFilesInfo() {
    try {
        if (!fs.existsSync(FILES_DB_PATH)) return [];
        const data = fs.readFileSync(FILES_DB_PATH, 'utf8').trim();
        return data ? JSON.parse(data) : [];
    } catch (e) {
        return [];
    }
}

function saveFilesInfo(files) {
    fs.writeFileSync(FILES_DB_PATH, JSON.stringify(files, null, 2));
}

// 修改上传接口记录归属
app.post('/api/upload', (req, res) => {
    upload.single('file')(req, res, (err) => {
        const token = req.cookies.token;
        if (!token) return res.status(401).send({ message: '请先登录' });

        let currentUser = '';
        try {
            currentUser = jwt.verify(token, JWT_SECRET).username;
        } catch(e) {
            return res.status(401).send({ message: '登录已过期' });
        }

        if (err) {
            if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).send({ message: '文件大小超过 100KB 限制' });
            return res.status(400).send({ message: err.message });
        }
        
        if (!req.file) return res.status(400).send({ message: '未找到上传文件' });

        // 记录所有权
        const filesInfo = loadFilesInfo();
        filesInfo.push({ filename: req.file.filename, owner: currentUser });
        saveFilesInfo(filesInfo);

        res.send({ message: '文件上传成功', filename: req.file.filename });
    });
});

const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const ADMIN_TOKEN_PATH = path.join(__dirname, 'token.json');
const ADMIN_SECRET_PATH = path.join(__dirname, 'admin_2fa.json');

// 初始化管理员 Token
if (!fs.existsSync(ADMIN_TOKEN_PATH)) {
    const adminToken = require('crypto').randomBytes(32).toString('hex');
    fs.writeFileSync(ADMIN_TOKEN_PATH, JSON.stringify({ key: adminToken }, null, 2));
    console.log('--- 管理员首次启动密钥已生成 ---');
    console.log('密钥路径:', ADMIN_TOKEN_PATH);
    console.log('密钥内容:', adminToken);
    console.log('-------------------------------');
}

// 管理员登录/验证接口
app.post('/api/admin/login', async (req, res) => {
    const { key, otpToken } = req.body;
    
    // 方式 1: 使用 token.json 密钥登录
    const savedToken = JSON.parse(fs.readFileSync(ADMIN_TOKEN_PATH, 'utf8')).key;
    if (key === savedToken) {
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '2h' });
        res.cookie('admin_token', token, { httpOnly: true, path: '/' });
        return res.send({ message: '管理员登录成功（通过密钥）' });
    }

    // 方式 2: 使用 2FA 登录
    if (fs.existsSync(ADMIN_SECRET_PATH) && otpToken) {
        const secret = JSON.parse(fs.readFileSync(ADMIN_SECRET_PATH, 'utf8')).base32;
        const verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token: otpToken
        });
        if (verified) {
            const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '2h' });
            res.cookie('admin_token', token, { httpOnly: true, path: '/' });
            return res.send({ message: '管理员登录成功（通过 2FA）' });
        }
    }

    res.status(401).send({ message: '管理员验证失败' });
});

// 设置 2FA 接口 (仅限已通过密钥登录的管理员)
app.get('/api/admin/setup-2fa', (req, res) => {
    const token = req.cookies.admin_token;
    if (!token) return res.status(401).send({ message: '未授权' });

    const secret = speakeasy.generateSecret({ name: 'Resource Depot Admin' });
    fs.writeFileSync(ADMIN_SECRET_PATH, JSON.stringify(secret));
    
    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
        res.send({ qrCode: data_url, secret: secret.base32 });
    });
});

// 管理员权限检查中间件
const adminOnly = (req, res, next) => {
    const token = req.cookies.admin_token;
    if (!token) return res.status(403).send({ message: '需要管理员权限' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === 'admin') return next();
        res.status(403).send({ message: '非管理员' });
    } catch(e) {
        res.status(403).send({ message: '验证失效' });
    }
};

// 修改删除接口：管理员可删除任何文件
app.delete('/api/delete/:filename', (req, res) => {
    const userToken = req.cookies.token;
    const adminToken = req.cookies.admin_token;
    
    let isAdmin = false;
    let currentUser = '';

    if (adminToken) {
        try {
            const decoded = jwt.verify(adminToken, JWT_SECRET);
            if (decoded.role === 'admin') isAdmin = true;
        } catch(e) {}
    }

    if (!isAdmin && !userToken) return res.status(401).send({ message: '请先登录' });

    try {
        if (!isAdmin) {
            currentUser = jwt.verify(userToken, JWT_SECRET).username;
        }

        const filename = req.params.filename;
        const filesInfo = loadFilesInfo();
        const fileRecord = filesInfo.find(f => f.filename === filename);

        if (!fileRecord) return res.status(404).send({ message: '找不到该文件记录' });
        
        // 权限判断：管理员 或 拥有者
        if (!isAdmin && fileRecord.owner !== currentUser) {
            return res.status(403).send({ message: '你没有权限删除他人的文件' });
        }

        const filePath = path.join(__dirname, '../uploads', filename);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

        saveFilesInfo(filesInfo.filter(f => f.filename !== filename));
        res.send({ message: isAdmin ? '管理员已强制删除文件' : '文件已成功删除' });
    } catch (e) {
        res.status(401).send({ message: '验证失败' });
    }
});

app.listen(3000, () => console.log('服务器运行在 http://localhost:3000'));
