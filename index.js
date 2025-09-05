// =================================================================
// IMPORTS E CONFIGURAÇÕES INICIAIS
// =================================================================
require('dotenv').config();

const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Sequelize, DataTypes, Op } = require('sequelize');
const pg = require('pg');
const PgStore = require('connect-pg-simple')(session);

const app = express();
const port = process.env.PORT || 3000;


// =================================================================
// BANCO DE DADOS E MODELOS (SEQUELIZE)
// =================================================================
let sequelize;

if (process.env.NODE_ENV === 'production') {
    sequelize = new Sequelize(process.env.DATABASE_URL, {
        dialect: 'postgres',
        protocol: 'postgres',
        dialectOptions: {
            ssl: { require: true, rejectUnauthorized: false }
        },
        timezone: '-03:00'
    });
} else {
    sequelize = new Sequelize({
        dialect: 'sqlite',
        storage: './database.sqlite'
    });
}

// Modelos
const Empresa = sequelize.define('Empresa', {
    nome: { type: DataTypes.STRING, allowNull: false },
    cnpj: { type: DataTypes.STRING, allowNull: true, unique: true }
});
const User = sequelize.define('User', {
    nome: { type: DataTypes.STRING, allowNull: false },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    senha: { type: DataTypes.STRING, allowNull: false },
    role: { type: DataTypes.STRING, defaultValue: 'funcionario' },
    horarioEntrada: { type: DataTypes.TIME, allowNull: true },
    horarioSaida: { type: DataTypes.TIME, allowNull: true }
});
const RegistroPonto = sequelize.define('RegistroPonto', {
    timestamp: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
    tipo: { type: DataTypes.STRING, allowNull: false }
});
const Ferias = sequelize.define('Ferias', {
    dataInicio: { type: DataTypes.DATEONLY, allowNull: false },
    dataFim: { type: DataTypes.DATEONLY, allowNull: false }
});
const Configuracao = sequelize.define('Configuracao', {
    chave: { type: DataTypes.STRING, allowNull: false },
    valor: { type: DataTypes.STRING, allowNull: false }
});

// Relacionamentos
Empresa.hasMany(User);
User.belongsTo(Empresa);
Empresa.hasMany(Configuracao);
Configuracao.belongsTo(Empresa);
User.hasMany(RegistroPonto);
RegistroPonto.belongsTo(User);
User.hasMany(Ferias);
Ferias.belongsTo(User);


// =================================================================
// CONFIGURAÇÃO DO EXPRESS E MIDDLEWARES
// =================================================================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', true);
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// --- CONFIGURAÇÃO DA SESSÃO COM POSTGRESQL ---
const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(session({
    store: new PgStore({
        pool: pool,
        tableName: 'session'
    }),
    secret: 'um-segredo-muito-forte-para-proteger-as-sessoes',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 dias
}));


// =================================================================
// MIDDLEWARES E FUNÇÕES AUXILIARES
// =================================================================
function checarAutenticacao(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

async function checarAutorizacaoRH(req, res, next) {
    const user = await User.findByPk(req.session.userId);
    if (user && user.role === 'rh') {
        next();
    } else {
        res.status(403).send('Acesso negado. Você não tem permissão para acessar esta página.');
    }
}

function restringirPorIP(req, res, next) {
    const allowedIps = (process.env.ALLOWED_IPS || '').split(',');
    if (allowedIps.length === 0 || allowedIps[0] === '') {
        return next();
    }
    const userIp = req.ip;
    if (allowedIps.includes(userIp) || userIp === '::1') {
        next();
    } else {
        res.status(403).send('Acesso negado. Você só pode bater o ponto a partir da rede da empresa.');
    }
}

function calcularHorasTrabalhadas(registros) {
    const registrosDoDia = registros || [];
    const entrada = registrosDoDia.find(r => r.tipo === 'Entrada');
    const saidaAlmoco = registrosDoDia.find(r => r.tipo === 'Saida Almoço');
    const voltaAlmoco = registrosDoDia.find(r => r.tipo === 'Volta Almoço');
    const saida = registrosDoDia.find(r => r.tipo === 'Saida');
    if (!entrada || !saida) {
        return 'Jornada em aberto';
    }
    const entradaTimestamp = new Date(entrada.timestamp);
    const saidaTimestamp = new Date(saida.timestamp);
    let intervaloMs = 0;
    if (saidaAlmoco && voltaAlmoco) {
        intervaloMs = new Date(voltaAlmoco.timestamp) - new Date(saidaAlmoco.timestamp);
    }
    const totalTrabalhadoMs = (saidaTimestamp - entradaTimestamp) - intervaloMs;
    const horas = Math.floor(totalTrabalhadoMs / 3600000);
    const minutos = Math.floor((totalTrabalhadoMs % 3600000) / 60000);
    return `${horas.toString().padStart(2, '0')}h ${minutos.toString().padStart(2, '0')}m`;
}

function getHorarioExpediente(usuario, data) {
    const horarioPadrao = { entrada: '09:00:00', saida: '18:00:00' };
    const horario = {
        entrada: usuario.horarioEntrada || horarioPadrao.entrada,
        saida: usuario.horarioSaida || horarioPadrao.saida
    };
    if (data.getDay() === 5) { // Sexta-feira
        const [horaEntrada, minutoEntrada, segundoEntrada] = horario.entrada.split(':');
        horario.entrada = `${(parseInt(horaEntrada, 10) - 1).toString().padStart(2, '0')}:${minutoEntrada}:${segundoEntrada}`;
        const [horaSaida, minutoSaida, segundoSaida] = horario.saida.split(':');
        horario.saida = `${(parseInt(horaSaida, 10) - 1).toString().padStart(2, '0')}:${minutoSaida}:${segundoSaida}`;
    }
    return horario;
}


// =================================================================
// ROTAS DA APLICAÇÃO
// =================================================================

// --- Rota de Cadastro de Empresa ---
app.get('/empresa/cadastrar', (req, res) => {
    res.render('empresa_cadastro');
});

app.post('/empresa/cadastrar', async (req, res) => {
    const { nomeEmpresa, cnpj, nomeAdmin, emailAdmin, senhaAdmin } = req.body;
    const t = await sequelize.transaction();
    try {
        const novaEmpresa = await Empresa.create({ nome: nomeEmpresa, cnpj: cnpj }, { transaction: t });
        const senhaHash = await bcrypt.hash(senhaAdmin, 10);
        await User.create({
            nome: nomeAdmin,
            email: emailAdmin,
            senha: senhaHash,
            role: 'rh',
            EmpresaId: novaEmpresa.id
        }, { transaction: t });
        await t.commit();
        res.redirect('/rh/login');
    } catch (error) {
        await t.rollback();
        console.error("Erro no cadastro de empresa:", error);
        res.status(500).send('Erro ao cadastrar nova empresa. O email ou CNPJ já pode estar em uso.');
    }
});

// --- Rotas de Autenticação ---
app.get('/cadastro', checarAutenticacao, checarAutorizacaoRH, (req, res) => {
    res.render('cadastro');
});

app.post('/cadastro', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    const { nome, email, senha } = req.body;
    try {
        const senhaHash = await bcrypt.hash(senha, 10);
        await User.create({
            nome, email, senha: senhaHash,
            EmpresaId: req.session.empresaId
        });
        res.redirect('/rh/dashboard');
    } catch (error) {
        console.error("Erro no cadastro de funcionário:", error);
        res.status(500).send('Erro ao cadastrar funcionário. O e-mail já pode estar em uso.');
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { email, senha } = req.body;
    const user = await User.findOne({ where: { email, role: 'funcionario' } });
    if (user && await bcrypt.compare(senha, user.senha)) {
        req.session.userId = user.id;
        req.session.userRole = user.role;
        req.session.empresaId = user.EmpresaId;
        res.redirect('/dashboard');
    } else {
        res.render('login', { error: 'Email ou senha incorretos.' });
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) { return res.redirect('/dashboard'); }
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// --- Rotas de Autenticação do RH ---
app.get('/rh/login', (req, res) => {
    res.render('rh_login');
});

app.post('/rh/login', async (req, res) => {
    const { email, senha } = req.body;
    const user = await User.findOne({ where: { email, role: 'rh' } });
    if (user && await bcrypt.compare(senha, user.senha)) {
        req.session.userId = user.id;
        req.session.userRole = user.role;
        req.session.empresaId = user.EmpresaId;
        res.redirect('/rh/dashboard');
    } else {
        res.render('rh_login', { error: 'Credenciais inválidas ou sem permissão de acesso.' });
    }
});


// --- Rotas Principais (Protegidas) ---
app.get('/dashboard', checarAutenticacao, async (req, res) => {
    const user = await User.findByPk(req.session.userId);
    const hoje = new Date();
    hoje.setHours(0, 0, 0, 0);
    const registros = await RegistroPonto.findAll({
        where: { UserId: req.session.userId, timestamp: { [Op.gte]: hoje } },
        order: [['timestamp', 'ASC']]
    });
    res.render('dashboard', { user, registros, query: req.query });
});

app.post('/registrar', checarAutenticacao, restringirPorIP, async (req, res) => {
    try {
        const userId = req.session.userId;
        const hoje = new Date();
        hoje.setHours(0, 0, 0, 0);
        const registrosDoDia = await RegistroPonto.findAll({ where: { UserId: userId, timestamp: { [Op.gte]: hoje } }, order: [['timestamp', 'ASC']] });
        let tipoDeBatida = '';
        switch (registrosDoDia.length) {
            case 0: tipoDeBatida = 'Entrada'; break;
            case 1: tipoDeBatida = 'Saida Almoço'; break;
            case 2: tipoDeBatida = 'Volta Almoço'; break;
            case 3: tipoDeBatida = 'Saida'; break;
            default: return res.redirect('/dashboard?mensagem=ciclo_finalizado');
        }
        await RegistroPonto.create({ UserId: userId, tipo: tipoDeBatida });
        res.redirect('/dashboard');
    } catch (error) {
        console.error("Erro ao registrar ponto:", error);
        res.status(500).send('Ocorreu um erro ao registrar o ponto.');
    }
});

// --- Rotas do RH (Multi-Tenant) ---
app.get('/rh/dashboard', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        const todosUsuarios = await User.findAll({ where: { role: 'funcionario', EmpresaId: empresaId }, order: [['nome', 'ASC']] });
        const hoje = new Date();
        const inicioDoDia = new Date();
        inicioDoDia.setHours(0, 0, 0, 0);
        const idsDosFuncionarios = todosUsuarios.map(u => u.id);
        const [registrosDeHoje, todasFerias, configAlmoco] = await Promise.all([
            RegistroPonto.findAll({ where: { timestamp: { [Op.gte]: inicioDoDia }, UserId: idsDosFuncionarios }, include: User, order: [['UserId', 'ASC'], ['timestamp', 'ASC']] }),
            Ferias.findAll({ where: { UserId: idsDosFuncionarios }, order: [['dataInicio', 'DESC']] }),
            Configuracao.findOne({ where: { chave: 'duracao_almoco_minutos', EmpresaId: empresaId } })
        ]);
        const duracaoAlmocoAtual = configAlmoco ? configAlmoco.valor : '60';
        const registrosPorUsuario = {};
        registrosDeHoje.forEach(r => { (registrosPorUsuario[r.UserId] = registrosPorUsuario[r.UserId] || []).push(r); });
        const feriasPorUsuario = {};
        todasFerias.forEach(f => { (feriasPorUsuario[f.UserId] = feriasPorUsuario[f.UserId] || []).push(f); });
        const horasPorUsuario = {}, expedienteDoDiaPorUsuario = {};
        todosUsuarios.forEach(u => {
            horasPorUsuario[u.id] = calcularHorasTrabalhadas(registrosPorUsuario[u.id]);
            expedienteDoDiaPorUsuario[u.id] = getHorarioExpediente(u, hoje);
        });
        res.render('rh_dashboard', { usuarios: todosUsuarios, registros: registrosPorUsuario, horas: horasPorUsuario, expedientes: expedienteDoDiaPorUsuario, ferias: feriasPorUsuario, duracaoAlmocoAtual });
    } catch (error) {
        console.error("Erro na dashboard do RH:", error);
        res.status(500).send('Ocorreu um erro ao carregar a página do RH.');
    }
});

app.post('/rh/definir-horario/:userId', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { horarioEntrada, horarioSaida } = req.body;
        await User.update({ horarioEntrada, horarioSaida }, { where: { id: req.params.userId, EmpresaId: req.session.empresaId } });
        res.redirect('/rh/dashboard');
    } catch (error) {
        console.error("Erro ao definir horário:", error);
        res.status(500).send('Ocorreu um erro ao definir o horário.');
    }
});

app.post('/rh/ferias/agendar', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { funcionarioId, dataInicio, dataFim } = req.body;
        const funcionario = await User.findOne({ where: { id: funcionarioId, EmpresaId: req.session.empresaId }});
        if (!funcionario || !dataInicio || !dataFim || new Date(dataFim) < new Date(dataInicio)) {
            return res.status(400).send('Dados inválidos ou funcionário não pertence à sua empresa.');
        }
        await Ferias.create({ dataInicio, dataFim, UserId: funcionarioId });
        res.redirect('/rh/dashboard');
    } catch (error) {
        console.error("Erro ao agendar férias:", error);
        res.status(500).send('Ocorreu um erro ao agendar as férias.');
    }
});

app.post('/rh/configuracoes', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { duracaoAlmocoMinutos } = req.body;
        await Configuracao.upsert({
            chave: 'duracao_almoco_minutos',
            valor: duracaoAlmocoMinutos,
            EmpresaId: req.session.empresaId
        });
        res.redirect('/rh/dashboard');
    } catch (error) {
        console.error("Erro ao salvar configuração:", error);
        res.status(500).send('Ocorreu um erro ao salvar a configuração.');
    }
});

app.get('/rh/relatorios', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        const { dataInicio, dataFim, funcionarioId } = req.query;
        const hoje = new Date().toISOString().split('T')[0];
        const inicio = dataInicio || hoje;
        const fim = dataFim || hoje;
        const listaFuncionarios = await User.findAll({ where: { role: 'funcionario', EmpresaId: empresaId }, order: [['nome', 'ASC']] });
        let funcionariosParaProcessar = listaFuncionarios;
        if (funcionarioId && funcionarioId !== 'todos') {
            funcionariosParaProcessar = listaFuncionarios.filter(f => f.id == funcionarioId);
        }
        const idsDosFuncionarios = funcionariosParaProcessar.map(u => u.id);
        const [registrosNoPeriodo, todasFerias] = await Promise.all([
            RegistroPonto.findAll({ where: { timestamp: { [Op.between]: [`${inicio} 00:00:00`, `${fim} 23:59:59`] }, UserId: idsDosFuncionarios } }),
            Ferias.findAll({ where: { UserId: idsDosFuncionarios } })
        ]);
        const faltas = [];
        let dataAtual = new Date(`${inicio}T12:00:00Z`);
        const dataFinal = new Date(`${fim}T12:00:00Z`);
        while (dataAtual <= dataFinal) {
            const diaDaSemana = dataAtual.getUTCDay();
            if (diaDaSemana !== 0 && diaDaSemana !== 6) {
                const dataFormatada = dataAtual.toISOString().split('T')[0];
                for (const funcionario of funcionariosParaProcessar) {
                    const estaDeFerias = todasFerias.some(f => f.UserId === funcionario.id && new Date(dataFormatada) >= new Date(f.dataInicio) && new Date(dataFormatada) <= new Date(f.dataFim));
                    if (estaDeFerias) continue;
                    const temRegistro = registrosNoPeriodo.some(r => r.UserId === funcionario.id && new Date(r.timestamp).toISOString().split('T')[0] === dataFormatada);
                    if (!temRegistro) {
                        faltas.push({ nome: funcionario.nome, data: dataFormatada });
                    }
                }
            }
            dataAtual.setUTCDate(dataAtual.getUTCDate() + 1);
        }
        res.render('relatorios', {
            faltas: faltas, dataInicio: inicio, dataFim: fim,
            listaFuncionarios: listaFuncionarios,
            funcionarioIdSelecionado: funcionarioId || 'todos'
        });
    } catch (error) {
        console.error("Erro ao gerar relatório de faltas:", error);
        res.status(500).send('Ocorreu um erro ao gerar o relatório.');
    }
});

app.get('/rh/relatorios/download', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        const { dataInicio, dataFim, funcionarioId } = req.query;
        if (!dataInicio || !dataFim) {
            return res.status(400).send("Datas de início e fim são obrigatórias.");
        }
        const listaFuncionarios = await User.findAll({ where: { role: 'funcionario', EmpresaId: empresaId } });
        let funcionariosParaProcessar = listaFuncionarios;
        if (funcionarioId && funcionarioId !== 'todos') {
            funcionariosParaProcessar = listaFuncionarios.filter(f => f.id == funcionarioId);
        }
        const idsDosFuncionarios = funcionariosParaProcessar.map(u => u.id);
        const [registrosNoPeriodo, todasFerias] = await Promise.all([
            RegistroPonto.findAll({ where: { timestamp: { [Op.between]: [`${dataInicio} 00:00:00`, `${dataFim} 23:59:59`] }, UserId: idsDosFuncionarios } }),
            Ferias.findAll({ where: { UserId: idsDosFuncionarios } })
        ]);
        const faltas = [];
        let dataAtual = new Date(`${dataInicio}T12:00:00Z`);
        const dataFinal = new Date(`${fim}T12:00:00Z`);
        while (dataAtual <= dataFinal) {
            const diaDaSemana = dataAtual.getUTCDay();
            if (diaDaSemana !== 0 && diaDaSemana !== 6) {
                const dataFormatada = dataAtual.toISOString().split('T')[0];
                for (const funcionario of funcionariosParaProcessar) {
                    const estaDeFerias = todasFerias.some(f => f.UserId === funcionario.id && new Date(dataFormatada) >= new Date(f.dataInicio) && new Date(dataFormatada) <= new Date(f.dataFim));
                    if (estaDeFerias) continue;
                    const temRegistro = registrosNoPeriodo.some(r => r.UserId === funcionario.id && new Date(r.timestamp).toISOString().split('T')[0] === dataFormatada);
                    if (!temRegistro) {
                        faltas.push({
                            nome: funcionario.nome.replace(/,/g, ''),
                            data: new Date(dataFormatada + 'T12:00:00').toLocaleDateString('pt-BR')
                        });
                    }
                }
            }
            dataAtual.setUTCDate(dataAtual.getUTCDate() + 1);
        }
        const csvHeader = 'Funcionario,Data da Falta\n';
        const csvRows = faltas.map(f => `${f.nome},${f.data}`).join('\n');
        const csvContent = csvHeader + csvRows;
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="relatorio_faltas_${dataInicio}_a_${dataFim}.csv"`);
        res.status(200).send(csvContent);
    } catch (error) {
        console.error("Erro ao gerar download de relatório:", error);
        res.status(500).send('Ocorreu um erro ao gerar o arquivo.');
    }
});

// Rota Raiz
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});


// =================================================================
// FUNÇÕES E INICIALIZAÇÃO DO SERVIDOR
// =================================================================
async function iniciarSistema() {
    const adminEmail = process.env.ADMIN_EMAIL || 'rh@empresa.com';
    const adminSenha = process.env.ADMIN_SENHA || 'senha123';
    const [empresa, criada] = await Empresa.findOrCreate({
        where: { nome: 'Empresa Matriz (Padrão)' }
    });
    if (criada) { console.log(`Empresa Padrão (ID: ${empresa.id}) criada.`); }
    const userExists = await User.findOne({ where: { email: adminEmail } });
    if (!userExists) {
        const senhaHash = await bcrypt.hash(adminSenha, 10);
        await User.create({
            nome: 'Admin RH',
            email: adminEmail,
            senha: senhaHash,
            role: 'rh',
            EmpresaId: empresa.id
        });
        console.log('Usuário RH Padrão criado.');
    }
}

sequelize.sync().then(async () => {
    await iniciarSistema();
    app.listen(port, () => {
        console.log(`Servidor rodando em http://localhost:${port}`);
    });
}).catch(err => {
    console.error('Erro ao conectar ou sincronizar com o banco de dados:', err);
});