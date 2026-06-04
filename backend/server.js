const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Cấu hình Middleware
app.use(cors());
app.use(express.json());

// Kết nối tới database Supabase
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    },
    // Thêm dòng này để ép dùng IPv4 và tránh lỗi mạng
    host: 'db.mnkprezzjxprqggpzpnj.supabase.co',
    port: 5432,
    family: 4 
});

// Middleware xác thực Token JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: "Chưa cung cấp token xác thực" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Token không hợp lệ hoặc đã hết hạn" });
        req.user = user;
        next();
    });
};

// 1. API Đăng ký
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: "Thiếu tài khoản hoặc mật khẩu" });
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
            [username, hashedPassword]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: "Tên đăng nhập đã tồn tại" });
        res.status(500).json({ error: err.message });
    }
});

// 2. API Đăng nhập
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(400).json({ error: "Tài khoản không tồn tại" });
        
        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        
        if (isMatch) {
            const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
            res.json({ token, username: user.username });
        } else {
            res.status(400).json({ error: "Sai mật khẩu" });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. API Lấy danh sách bài báo
app.get('/api/articles', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT a.id, a.title, a.content, a.created_at, u.username as author 
             FROM articles a 
             JOIN users u ON a.author_id = u.id 
             ORDER BY a.created_at DESC`
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. API Thêm bài báo
app.post('/api/articles', authenticateToken, async (req, res) => {
    try {
        const { title, content } = req.body;
        if (!title || !content) return res.status(400).json({ error: "Thiếu tiêu đề hoặc nội dung" });
        const result = await pool.query(
            'INSERT INTO articles (title, content, author_id) VALUES ($1, $2, $3) RETURNING *',
            [title, content, req.user.id]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server đang chạy tại port: ${PORT}`));