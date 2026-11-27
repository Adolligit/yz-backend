const express = require('express');
const cors = require('cors');
require('dotenv').config();

// Sem um segredo forte, qualquer pessoa conseguiria forjar tokens de login.
// Por isso o servidor se recusa a iniciar nessa situação.
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    console.error('ERRO: defina JWT_SECRET no arquivo .env com pelo menos 32 caracteres.');
    console.error('Para gerar um: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
    process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

const authRoutes = require('./routes/auth');
const chatRoutes = require('./routes/chat');

app.use('/api/auth', authRoutes);
app.use('/api/chat', chatRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor Yz rodando na porta ${PORT}`);
});
