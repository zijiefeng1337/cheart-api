const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const multer = require('multer');

const app = express();
const JWT_SECRET = 'super-secret-key';
const GATEWAY_SECRET = 'gateway-secret-key';
const DB_PATH = path.join(__dirname, 'db.txt');
const upload = multer({ dest: 'uploads/' });

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

app.post('/api/upload', upload.single('file'), async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).send({ message: '请先登录' });
    
    if (!req.file) return res.status(400).send({ message: '未找到上传文件' });
    res.send({ message: '文件上传成功', filename: req.file.filename });
});

app.listen(3000, () => console.log('服务器运行在 http://localhost:3000'));
