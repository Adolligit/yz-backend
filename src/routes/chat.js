const express = require('express');
const { getYzaiResponse } = require('../services/ai');
const { requireAuth } = require('../middleware/auth');
const router = express.Router();

// POST /api/chat  { mensagem }   (exige token: o usuário já veio identificado pelo requireAuth)
router.post('/', requireAuth, async (req, res) => {
    const mensagem = String(req.body?.mensagem ?? '').trim();

    if (!mensagem) {
        return res.status(400).json({ error: 'Digite uma mensagem.' });
    }

    // req.user.id_usuario identifica quem está conversando.
    // Aqui entrará a lógica de gravar nas tabelas CONVERSA e MENSAGEM (próximo passo).
    const aiResponse = await getYzaiResponse(mensagem);
    res.json({ resposta: aiResponse });
});

module.exports = router;
