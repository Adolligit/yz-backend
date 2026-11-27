const jwt = require('jsonwebtoken');

// Protege uma rota: só deixa passar quem enviar um token JWT válido
// no cabeçalho  Authorization: Bearer <token>
function requireAuth(req, res, next) {
    const [tipo, token] = (req.headers.authorization || '').split(' ');

    if (tipo !== 'Bearer' || !token) {

        return res.status(401).json({ error: 'Faça login para continuar.' });
    }

    try {
        // algorithms fixo: impede tokens forjados com algoritmo "none"
        const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
        req.user = { id_usuario: payload.id_usuario };
        next();
    } catch (err) {
        const expirou = err.name === 'TokenExpiredError';
        return res.status(401).json({
            error: expirou
                ? 'Sua sessão expirou. Faça login novamente.'
                : 'Sessão inválida. Faça login novamente.',
        });
    }
}

module.exports = { requireAuth };
