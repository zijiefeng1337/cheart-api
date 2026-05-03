const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const JWT_SECRET = 'super-secret-key'; // 在生产环境中请使用环境变量

app.use(bodyParser.json());
app.use(cookieParser());
// 托管静态文件
app.use(express.static(path.join(__dirname, '../public')));

const fs = require('fs');

// 获取资源列表接口
app.get('/api/resources', (req, res) => {
    fs.readdir(path.join(__dirname, '../uploads'), (err, files) => {
        if (err) return res.status(500).send({ message: '读取资源失败' });
        res.send({ resources: files });
    });
});

// 模拟数据库
const users = [];

const axios = require('axios'); // 请确保安装了 axios

async function verifyTurnstile(token) {
    const res = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        secret: '0x4AAAAAADHW2HP8XJXbvAiaNpbLbXCZiaA',
        response: token
    });
    return res.data.success;
}

// 注册接口修改示例
app.post('/api/register', async (req, res) => {
    const { username, password, turnstileToken } = req.body;
    if (!(await verifyTurnstile(turnstileToken))) return res.status(403).send({ message: '验证失败' });
    // ... 原有逻辑
});

// 登录接口
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send({ message: '用户名或密码错误' });
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    res.send({ message: '登录成功' });
});

// 获取用户信息接口（示例）
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

const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

// ... 之前的代码

// 上传资源接口（已添加 Turnstile 校验）
app.post('/api/upload', upload.single('file'), async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).send({ message: '请先登录' });
    
    // 获取前端提交的 token
    const turnstileToken = req.body.turnstileToken;
    if (!turnstileToken || !(await verifyTurnstile(turnstileToken))) {
        return res.status(403).send({ message: '验证失败' });
    }

    if (!req.file) return res.status(400).send({ message: '未找到上传文件' });
    res.send({ message: '文件上传成功', filename: req.file.filename });
});

app.listen(3000, () => console.log('服务器运行在 http://localhost:3000'));