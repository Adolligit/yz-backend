const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/database');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const BCRYPT_ROUNDS = 12;
const TOKEN_VALIDADE = '7d';
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Hash "de mentira": no login, quando o e-mail não existe, ainda assim rodamos o
// bcrypt.compare com ele. Assim o tempo de resposta não revela quais e-mails existem.
const HASH_FALSO = bcrypt.hashSync('texto-qualquer-para-igualar-o-tempo', BCRYPT_ROUNDS);

// O driver do SQLite usa callbacks; estes dois atalhos permitem usar async/await.
const dbGet = (sql, params = []) =>
    new Promise((resolve, reject) =>
        db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row))));

const dbRun = (sql, params = []) =>
    new Promise((resolve, reject) =>
        db.run(sql, params, function (err) {
            if (err) return reject(err);
            resolve({ lastID: this.lastID });
        }));

function gerarToken(id_usuario) {
    return jwt.sign({ id_usuario }, process.env.JWT_SECRET, { expiresIn: TOKEN_VALIDADE });
}

// Nunca devolvemos a senha (nem o hash) para o front-end
function usuarioPublico(u) {
    return { id_usuario: u.id_usuario, nome: u.nome, email: u.email };
}

function erroDeEmailDuplicado(err) {
    return err && (err.code === 'SQLITE_CONSTRAINT' || /UNIQUE/i.test(err.message || ''));
}

// POST /api/auth/register  { nome, email, senha }
router.post('/register', async (req, res) => {
    try {
        const nome = String(req.body?.nome ?? '').trim();
        const email = String(req.body?.email ?? '').trim().toLowerCase();
        const senha = String(req.body?.senha ?? '');

        if (nome.length < 2 || nome.length > 100) {
            return res.status(400).json({ error: 'Informe seu nome (de 2 a 100 caracteres).' });
        }
        if (!EMAIL_REGEX.test(email) || email.length > 100) {
            return res.status(400).json({ error: 'Informe um e-mail válido.' });
        }
        if (senha.length < 8) {
            return res.status(400).json({ error: 'A senha deve ter pelo menos 8 caracteres.' });
        }
        // O bcrypt só considera os 72 primeiros bytes da senha
        if (Buffer.byteLength(senha, 'utf8') > 72) {
            return res.status(400).json({ error: 'A senha é muito longa (máximo de 72 caracteres).' });
        }

        const existente = await dbGet('SELECT id_usuario FROM USUARIO WHERE email = ?', [email]);
        if (existente) {
            return res.status(409).json({ error: 'Este e-mail já está cadastrado.' });
        }

        const hash = await bcrypt.hash(senha, BCRYPT_ROUNDS);
        const { lastID } = await dbRun(
            'INSERT INTO USUARIO (nome, email, senha) VALUES (?, ?, ?)',
            [nome, email, hash]
        );

        const usuario = { id_usuario: lastID, nome, email };
        res.status(201).json({ token: gerarToken(lastID), usuario });
    } catch (err) {
        // Duas pessoas cadastrando o mesmo e-mail ao mesmo tempo
        if (erroDeEmailDuplicado(err)) {
            return res.status(409).json({ error: 'Este e-mail já está cadastrado.' });
        }
        console.error('Erro no cadastro:', err);
        res.status(500).json({ error: 'Não foi possível criar a conta. Tente novamente.' });
    }
});

// POST /api/auth/login  { email, senha }
router.post('/login', async (req, res) => {
    try {
        const email = String(req.body?.email ?? '').trim().toLowerCase();
        const senha = String(req.body?.senha ?? '');

        if (!email || !senha) {
            return res.status(400).json({ error: 'Informe e-mail e senha.' });
        }

        const usuario = await dbGet(
            'SELECT id_usuario, nome, email, senha FROM USUARIO WHERE email = ?',
            [email]
        );

        // Contas criadas só por login social (futuro) terão senha vazia (NULL):
        // nesse caso também cai no HASH_FALSO e a tentativa é recusada.
        const senhaConfere = await bcrypt.compare(senha, usuario?.senha || HASH_FALSO);

        // Mesma mensagem para "e-mail não existe" e "senha errada", de propósito
        if (!usuario || !usuario.senha || !senhaConfere) {
            return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
        }

        res.json({ token: gerarToken(usuario.id_usuario), usuario: usuarioPublico(usuario) });
    } catch (err) {
        console.error('Erro no login:', err);
        res.status(500).json({ error: 'Não foi possível entrar agora. Tente novamente.' });
    }
});

// GET /api/auth/me  (exige token) -> o front usa ao abrir o app para saber quem está logado
router.get('/me', requireAuth, async (req, res) => {
    try {
        const usuario = await dbGet(
            'SELECT id_usuario, nome, email FROM USUARIO WHERE id_usuario = ?',
            [req.user.id_usuario]
        );
        if (!usuario) {
            return res.status(401).json({ error: 'Sessão inválida. Faça login novamente.' });
        }
        res.json({ usuario });
    } catch (err) {
        console.error('Erro ao buscar usuário:', err);
        res.status(500).json({ error: 'Erro ao carregar seus dados.' });
    }
});

module.exports = router;
