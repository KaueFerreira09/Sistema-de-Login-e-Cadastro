const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const db = require('./db');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = 3000;

// ====================
// MIDDLEWARES GLOBAIS
// ====================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// 👉 AQUI (antes das rotas)
app.use(express.static('public'));

// 👉 Session SEMPRE antes das rotas
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

// ====================
// ROTA INICIAL
// ====================
app.get('/', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard.html');
    }
    res.redirect('/login.html');
});

// ====================
// ROTA DE CADASTRO
// ====================
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        await db.query(
            'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)',
            [username, email, hashedPassword]
        );

        res.redirect('/login.html');
    } catch (err) {
        console.error(err);
        res.send('Erro no cadastro');
    }
});

// ====================
// ROTA DE LOGIN
// ====================
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await db.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (result.rowCount === 0) {
            return res.send('Usuário não encontrado');
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.send('Senha incorreta');
        }

        req.session.userId = user.id;
        res.redirect('/dashboard.html');
    } catch (err) {
        console.error(err);
        res.send('Erro ao logar');
    }
});

// ====================
// ROTA PROTEGIDA
// ====================
app.get('/dashboard.html', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login.html');
    }

    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// ====================
// LOGOUT
// ====================
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login.html');
    });
});

// ====================
// START SERVER
// ====================
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
