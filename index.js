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
const puppeteer = require('puppeteer-core');
const chromium = require('@sparticuz/chromium');
const ejs = require('ejs');


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

// --- CONFIGURAÇÃO DE SESSÃO INTELIGENTE ---
if (process.env.NODE_ENV === 'production') {
    // Em produção (Render), usa o PostgreSQL para as sessões
    const pool = new pg.Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
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
} else {
    // Localmente, continua usando o SQLite para as sessões
    const SQLiteStore = require('connect-sqlite3')(session);
    app.use(session({
        store: new SQLiteStore({ db: 'sessions.sqlite', concurrentDB: true }),
        secret: 'um-segredo-muito-forte-para-proteger-as-sessoes',
        resave: false,
        saveUninitialized: false,
        cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 dia
    }));
}


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

// ROTA PARA O FUNCIONÁRIO VER SEU PRÓPRIO RELATÓRIO
app.get('/meu-relatorio', checarAutenticacao, async (req, res) => {
    try {
        const { userId, empresaId } = req.session;
        const { dataInicio, dataFim } = req.query;

        // Se não houver datas, não carrega dados
        if (!dataInicio || !dataFim) {
            const hoje = new Date().toISOString().split('T')[0];
            return res.render('meu_relatorio', {
                relatorioAgrupado: null,
                dataInicioSelecionada: hoje,
                dataFimSelecionada: hoje
            });
        }

        const funcionario = await User.findByPk(userId);
        if (!funcionario) return res.status(404).send("Funcionário não encontrado.");

        // A lógica de busca e agrupamento de dados é muito parecida com a do RH
        const dataInicioObj = new Date(`${dataInicio}T00:00:00-03:00`);
        const dataFimObj = new Date(`${dataFim}T23:59:59-03:00`);

        const [registros, ferias, configAlmoco] = await Promise.all([
            RegistroPonto.findAll({ where: { UserId: userId, timestamp: { [Op.between]: [dataInicioObj, dataFimObj] } } }),
            Ferias.findAll({ where: { UserId: userId } }),
            Configuracao.findOne({ where: { chave: 'duracao_almoco_minutos', EmpresaId: empresaId } })
        ]);

        const duracaoAlmoco = configAlmoco ? parseInt(configAlmoco.valor, 10) : 60;
        const registrosDoFunc = registros.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

        const dadosFuncionario = {
            semanas: []
        };
        let semanaAtual = {};
        let dataAtualLoop = new Date(dataInicioObj);

        while (dataAtualLoop <= dataFimObj) {
            const diaDaSemana = dataAtualLoop.getDay();
            const diaString = dataAtualLoop.toISOString().split('T')[0];

            if (diaDaSemana > 0 && diaDaSemana < 6) {
                const registrosDoDia = registrosDoFunc.filter(r => new Date(r.timestamp).toISOString().split('T')[0] === diaString);
                const diaInfo = {
                    data: new Date(dataAtualLoop),
                    registros: registrosDoDia,
                    horasTrabalhadas: '00h 00m', saldoHoras: '', observacao: ''
                };

                const estaDeFerias = ferias.some(f => {
                    const inicio = new Date(f.dataInicio + 'T00:00:00-03:00');
                    const fim = new Date(f.dataFim + 'T23:59:59-03:00');
                    return dataAtualLoop >= inicio && dataAtualLoop <= fim;
                });

                if (estaDeFerias) { diaInfo.observacao = 'Férias'; }
                else if (registrosDoDia.length === 0) { diaInfo.observacao = 'Falta'; }

                if (registrosDoDia.length > 0) {
                    diaInfo.horasTrabalhadas = calcularHorasTrabalhadas(registrosDoDia);
                    if (diaInfo.horasTrabalhadas !== 'Jornada em aberto') {
                        const expediente = getHorarioExpediente(funcionario, dataAtualLoop);
                        const [hE, mE] = expediente.entrada.split(':').map(Number);
                        const [hS, mS] = expediente.saida.split(':').map(Number);
                        const jornadaMin = ((hS - hE) * 60) + (mS - mE) - duracaoAlmoco;
                        const [hT, mT] = diaInfo.horasTrabalhadas.replace('h ', 'm').slice(0, -1).split('m');
                        const trabalhadoMin = (parseInt(hT) * 60) + parseInt(mT);
                        const saldoMin = trabalhadoMin - jornadaMin;
                        const sinal = saldoMin >= 0 ? '+' : '-';
                        const hSaldo = Math.floor(Math.abs(saldoMin) / 60).toString().padStart(2, '0');
                        const mSaldo = (Math.abs(saldoMin) % 60).toString().padStart(2, '0');
                        diaInfo.saldoHoras = `${sinal}${hSaldo}h ${mSaldo}m`;
                    }
                }
                const dias = ['domingo', 'segunda', 'terca', 'quarta', 'quinta', 'sexta'];
                semanaAtual[dias[diaDaSemana]] = diaInfo;
            }

            if (diaDaSemana === 5) {
                if (Object.keys(semanaAtual).length > 0) dadosFuncionario.semanas.push(semanaAtual);
                semanaAtual = {};
            }
            dataAtualLoop.setDate(dataAtualLoop.getDate() + 1);
        }

        if (Object.keys(semanaAtual).length > 0) {
            dadosFuncionario.semanas.push(semanaAtual);
        }

        res.render('meu_relatorio', {
            relatorioAgrupado: dadosFuncionario,
            dataInicioSelecionada: dataInicio,
            dataFimSelecionada: dataFim
        });

    } catch (error) {
        console.error("Erro ao gerar relatório do funcionário:", error);
        res.status(500).send('Ocorreu um erro.');
    }
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

// ROTA PARA EXCLUIR FUNCIONÁRIO
app.post('/rh/funcionario/excluir/:id', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        const funcionarioId = req.params.id;

        await User.destroy({
            where: {
                id: funcionarioId,
                EmpresaId: empresaId,
                role: 'funcionario'
            }
        });

        res.redirect('/rh/dashboard');
    } catch (error) {
        console.error("Erro ao excluir funcionário:", error);
        res.status(500).send('Ocorreu um erro ao tentar excluir o funcionário.');
    }
});

// index.js -> Adicione estas duas rotas

// ROTA PARA MOSTRAR A PÁGINA DE EDIÇÃO
app.get('/rh/funcionario/editar/:id', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        const funcionarioId = req.params.id;

        const funcionario = await User.findOne({
            where: {
                id: funcionarioId,
                EmpresaId: empresaId,
                role: 'funcionario'
            }
        });

        if (!funcionario) {
            return res.status(404).send('Funcionário não encontrado ou não pertence à sua empresa.');
        }

        res.render('editar_funcionario', { funcionario: funcionario });
    } catch (error) {
        console.error("Erro ao carregar página de edição:", error);
        res.status(500).send('Ocorreu um erro.');
    }
});

// ROTA PARA SALVAR OS DADOS EDITADOS
app.post('/rh/funcionario/editar/:id', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        const funcionarioId = req.params.id;
        const { nome, email, senha } = req.body;

        const dadosParaAtualizar = { nome, email };

        // Se uma nova senha foi fornecida, criptografa e adiciona aos dados
        if (senha) {
            dadosParaAtualizar.senha = await bcrypt.hash(senha, 10);
        }

        await User.update(dadosParaAtualizar, {
            where: {
                id: funcionarioId,
                EmpresaId: empresaId
            }
        });

        res.redirect('/rh/dashboard');
    } catch (error) {
        console.error("Erro ao salvar edição do funcionário:", error);
        res.status(500).send('Ocorreu um erro ao salvar as alterações.');
    }
});

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
        const funcionario = await User.findOne({ where: { id: funcionarioId, EmpresaId: req.session.empresaId } });
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

// ROTA TOTALMENTE REESTRUTURADA PARA EXIBIR RELATÓRIO SEMANAL
app.get('/rh/relatorios/folha-ponto', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        const { dataInicio, dataFim, funcionarioId } = req.query;

        const hoje = new Date().toISOString().split('T')[0];
        const listaFuncionarios = await User.findAll({ where: { role: 'funcionario', EmpresaId: empresaId }, order: [['nome', 'ASC']] });

        if (!dataInicio || !dataFim || !funcionarioId) {
            return res.render('folha_ponto_semanal', {
                relatorioAgrupado: null,
                listaFuncionarios,
                dataInicioSelecionada: hoje,
                dataFimSelecionada: hoje,
                funcionarioIdSelecionado: null
            });
        }

        const dataInicioObj = new Date(`${dataInicio}T00:00:00-03:00`);
        const dataFimObj = new Date(`${dataFim}T23:59:59-03:00`);

        let funcionariosParaProcessar = (funcionarioId === 'todos') ? listaFuncionarios : listaFuncionarios.filter(f => f.id == funcionarioId);

        if (funcionariosParaProcessar.length === 0) return res.status(404).send("Nenhum funcionário encontrado.");

        const idsDosFuncionarios = funcionariosParaProcessar.map(f => f.id);
        const [registros, ferias, configAlmoco] = await Promise.all([
            RegistroPonto.findAll({ where: { UserId: idsDosFuncionarios, timestamp: { [Op.between]: [dataInicioObj, dataFimObj] } } }),
            Ferias.findAll({ where: { UserId: idsDosFuncionarios } }),
            Configuracao.findOne({ where: { chave: 'duracao_almoco_minutos', EmpresaId: empresaId } })
        ]);

        const duracaoAlmoco = configAlmoco ? parseInt(configAlmoco.valor, 10) : 60;

        const relatorioAgrupado = [];

        for (const funcionario of funcionariosParaProcessar) {
            const dadosFuncionario = {
                id: funcionario.id,
                nome: funcionario.nome,
                semanas: []
            };

            const registrosDoFunc = registros.filter(r => r.UserId === funcionario.id).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            const feriasDoFunc = ferias.filter(f => f.UserId === funcionario.id);

            let semanaAtual = {};
            let dataAtualLoop = new Date(dataInicioObj);

            while (dataAtualLoop <= dataFimObj) {
                const diaDaSemana = dataAtualLoop.getDay();
                const diaString = dataAtualLoop.toISOString().split('T')[0];

                if (diaDaSemana > 0 && diaDaSemana < 6) {
                    const registrosDoDia = registrosDoFunc.filter(r => new Date(r.timestamp).toISOString().split('T')[0] === diaString);
                    const diaInfo = {
                        data: new Date(dataAtualLoop),
                        registros: registrosDoDia,
                        horasTrabalhadas: '00h 00m', saldoHoras: '', observacao: ''
                    };

                    const estaDeFerias = feriasDoFunc.some(f => {
                        const inicio = new Date(f.dataInicio + 'T00:00:00-03:00');
                        const fim = new Date(f.dataFim + 'T23:59:59-03:00');
                        return dataAtualLoop >= inicio && dataAtualLoop <= fim;
                    });

                    if (estaDeFerias) { diaInfo.observacao = 'Férias'; }
                    else if (registrosDoDia.length === 0) { diaInfo.observacao = 'Falta'; }

                    if (registrosDoDia.length > 0) {
                        diaInfo.horasTrabalhadas = calcularHorasTrabalhadas(registrosDoDia);
                        if (diaInfo.horasTrabalhadas !== 'Jornada em aberto') {
                            const expediente = getHorarioExpediente(funcionario, dataAtualLoop);
                            const [hE, mE] = expediente.entrada.split(':').map(Number);
                            const [hS, mS] = expediente.saida.split(':').map(Number);
                            const jornadaMin = ((hS - hE) * 60) + (mS - mE) - duracaoAlmoco;
                            const [hT, mT] = diaInfo.horasTrabalhadas.replace('h ', 'm').slice(0, -1).split('m');
                            const trabalhadoMin = (parseInt(hT) * 60) + parseInt(mT);
                            const saldoMin = trabalhadoMin - jornadaMin;
                            const sinal = saldoMin >= 0 ? '+' : '-';
                            const hSaldo = Math.floor(Math.abs(saldoMin) / 60).toString().padStart(2, '0');
                            const mSaldo = (Math.abs(saldoMin) % 60).toString().padStart(2, '0');
                            diaInfo.saldoHoras = `${sinal}${hSaldo}h ${mSaldo}m`;
                        }
                    }

                    const dias = ['domingo', 'segunda', 'terca', 'quarta', 'quinta', 'sexta'];
                    semanaAtual[dias[diaDaSemana]] = diaInfo;
                }

                if (diaDaSemana === 5) {
                    if (Object.keys(semanaAtual).length > 0) {
                        dadosFuncionario.semanas.push(semanaAtual);
                    }
                    semanaAtual = {};
                }

                dataAtualLoop.setDate(dataAtualLoop.getDate() + 1);
            }

            // Após o fim do loop, salva a última semana processada, caso ela não esteja vazia
            if (Object.keys(semanaAtual).length > 0) {
                dadosFuncionario.semanas.push(semanaAtual);
            }

            relatorioAgrupado.push(dadosFuncionario);
        }

        res.render('folha_ponto_semanal', {
            relatorioAgrupado,
            listaFuncionarios,
            dataInicioSelecionada: dataInicio,
            dataFimSelecionada: dataFim,
            funcionarioIdSelecionado: funcionarioId
        });

    } catch (error) {
        console.error("Erro ao gerar folha de ponto semanal:", error);
        res.status(500).send('Ocorreu um erro ao gerar o relatório detalhado.');
    }
});

// ROTA PARA FAZER O DOWNLOAD DA FOLHA DE PONTO EM CSV
app.get('/rh/relatorios/folha-ponto/download', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        const { dataInicio, dataFim, funcionarioId } = req.query;

        if (!dataInicio || !dataFim || !funcionarioId) {
            return res.status(400).send("Parâmetros de filtro ausentes.");
        }

        // =================================================================
        // REUTILIZAÇÃO DA LÓGICA DE BUSCA E PROCESSAMENTO DE DADOS
        // (Este trecho é quase idêntico ao da rota anterior)
        // =================================================================
        const dataInicioObj = new Date(`${dataInicio}T00:00:00-03:00`);
        const dataFimObj = new Date(`${dataFim}T23:59:59-03:00`);

        let funcionariosParaProcessar = [];
        if (funcionarioId === 'todos') {
            funcionariosParaProcessar = await User.findAll({ where: { role: 'funcionario', EmpresaId: empresaId }, order: [['nome', 'ASC']] });
        } else {
            const func = await User.findOne({ where: { id: funcionarioId, EmpresaId: empresaId } });
            if (func) funcionariosParaProcessar.push(func);
        }

        if (funcionariosParaProcessar.length === 0) {
            return res.status(404).send("Nenhum funcionário encontrado.");
        }

        const idsDosFuncionarios = funcionariosParaProcessar.map(f => f.id);
        const [registros, ferias, configAlmoco] = await Promise.all([
            RegistroPonto.findAll({ where: { UserId: idsDosFuncionarios, timestamp: { [Op.between]: [dataInicioObj, dataFimObj] } }, order: [['timestamp', 'ASC']] }),
            Ferias.findAll({ where: { UserId: idsDosFuncionarios } }),
            Configuracao.findOne({ where: { chave: 'duracao_almoco_minutos', EmpresaId: empresaId } })
        ]);

        const duracaoAlmoco = configAlmoco ? parseInt(configAlmoco.valor, 10) : 60;
        const registrosPorUsuario = {};
        registros.forEach(r => { (registrosPorUsuario[r.UserId] = registrosPorUsuario[r.UserId] || []).push(r); });
        const feriasPorUsuario = {};
        ferias.forEach(f => { (feriasPorUsuario[f.UserId] = feriasPorUsuario[f.UserId] || []).push(f); });

        const relatorio = [];
        let dataAtualLoop = new Date(dataInicioObj);
        while (dataAtualLoop <= dataFimObj) {
            for (const funcionario of funcionariosParaProcessar) {
                const diaString = dataAtualLoop.toISOString().split('T')[0];
                const diaDaSemana = dataAtualLoop.getDay();
                const registrosDoDia = (registrosPorUsuario[funcionario.id] || []).filter(r => new Date(r.timestamp).toISOString().split('T')[0] === diaString);

                const diaInfo = { /* ... (lógica interna idêntica para montar o diaInfo) ... */ };
                Object.assign(diaInfo, {
                    funcionarioNome: funcionario.nome,
                    data: new Date(dataAtualLoop),
                    registros: registrosDoDia,
                    horasTrabalhadas: '00h 00m',
                    saldoHoras: '',
                    observacao: ''
                });

                if (diaDaSemana === 0 || diaDaSemana === 6) { diaInfo.observacao = 'Fim de semana'; } else {
                    const feriasDoFunc = feriasPorUsuario[funcionario.id] || [];
                    const estaDeFerias = feriasDoFunc.some(f => {
                        const inicioFerias = new Date(f.dataInicio + 'T00:00:00-03:00'); const fimFerias = new Date(f.dataFim + 'T23:59:59-03:00');
                        return dataAtualLoop >= inicioFerias && dataAtualLoop <= fimFerias;
                    });
                    if (estaDeFerias) { diaInfo.observacao = 'Férias'; } else if (diaInfo.registros.length === 0) { diaInfo.observacao = 'Falta'; }
                }
                if (diaInfo.registros.length > 0) {
                    diaInfo.horasTrabalhadas = calcularHorasTrabalhadas(diaInfo.registros);
                    const expediente = getHorarioExpediente(funcionario, dataAtualLoop);
                    const [hEntrada, mEntrada] = expediente.entrada.split(':').map(Number); const [hSaida, mSaida] = expediente.saida.split(':').map(Number);
                    const jornadaEsperadaMinutos = ((hSaida - hEntrada) * 60) + (mSaida - mEntrada) - duracaoAlmoco;
                    if (diaInfo.horasTrabalhadas !== 'Jornada em aberto') {
                        const [hTrab, mTrab] = diaInfo.horasTrabalhadas.replace('h ', 'm').slice(0, -1).split('m');
                        const totalTrabalhadoMinutos = (parseInt(hTrab) * 60) + parseInt(mTrab);
                        const saldoMinutos = totalTrabalhadoMinutos - jornadaEsperadaMinutos;
                        const sinal = saldoMinutos >= 0 ? '+' : '-';
                        const hSaldo = Math.floor(Math.abs(saldoMinutos) / 60).toString().padStart(2, '0');
                        const mSaldo = (Math.abs(saldoMinutos) % 60).toString().padStart(2, '0');
                        diaInfo.saldoHoras = `${sinal}${hSaldo}h ${mSaldo}m`;
                    }
                }
                relatorio.push(diaInfo);
            }
            dataAtualLoop.setDate(dataAtualLoop.getDate() + 1);
        }
        relatorio.sort((a, b) => a.data - b.data || a.funcionarioNome.localeCompare(b.funcionarioNome));

        // =================================================================
        // LÓGICA PARA GERAR O ARQUIVO CSV
        // =================================================================
        const isForAll = funcionarioId === 'todos';
        let csvHeader = (isForAll ? 'Funcionario,' : '') + 'Data,Dia da Semana,Registros,Total Trabalhado,Saldo do Dia,Observacao\n';

        const csvRows = relatorio.map(dia => {
            const funcionario = isForAll ? `"${dia.funcionarioNome.replace(/"/g, '""')}",` : '';
            const data = dia.data.toLocaleDateString('pt-BR');
            const diaSemana = dia.data.toLocaleDateString('pt-BR', { weekday: 'long' });

            // Formata os registros em uma única string, separados por " | "
            const registrosStr = dia.registros.map(r => `${r.tipo}: ${new Date(r.timestamp).toLocaleTimeString('pt-BR')}`).join(' | ');

            // LINHA CORRIGIDA AQUI
            return `${funcionario}${data},${diaSemana},"${registrosStr}","${dia.horasTrabalhadas}","${dia.saldoHoras}","${dia.observacao.replace(/"/g, '""')}"`;
        }).join('\n');

        const csvContent = "\uFEFF" + csvHeader + csvRows; // Adiciona BOM para o Excel entender o UTF-8

        const filename = `folha_ponto_${dataInicio}_a_${dataFim}.csv`;
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.status(200).send(Buffer.from(csvContent, 'utf-8'));

    } catch (error) {
        console.error("Erro ao gerar download da folha de ponto:", error);
        res.status(500).send('Ocorreu um erro ao gerar o arquivo.');
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
            RegistroPonto.findAll({ where: { timestamp: { [Op.between]: [`${dataInicio} 00:00:00`, `${fim} 23:59:59`] }, UserId: idsDosFuncionarios } }),
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

// ROTA PARA GERAR O ESPELHO DE PONTO EM PDF - CORRIGIDA PARA RENDER
app.get('/rh/relatorios/folha-ponto/pdf', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        const { dataInicio, dataFim, funcionarioId } = req.query;

        if (!dataInicio || !dataFim || !funcionarioId) {
            return res.status(400).send("Parâmetros de filtro ausentes para gerar o PDF.");
        }

        // ... (TODA A SUA LÓGICA DE BUSCAR E PROCESSAR OS DADOS CONTINUA EXATAMENTE A MESMA AQUI) ...
        const listaFuncionarios = await User.findAll({ where: { role: 'funcionario', EmpresaId: empresaId }, order: [['nome', 'ASC']] });
        let funcionariosParaProcessar = (funcionarioId === 'todos') ? listaFuncionarios : listaFuncionarios.filter(f => f.id == funcionarioId);
        const empresa = await Empresa.findByPk(empresaId);
        const dataInicioObj = new Date(`${dataInicio}T00:00:00-03:00`);
        const dataFimObj = new Date(`${dataFim}T23:59:59-03:00`);
        const idsDosFuncionarios = funcionariosParaProcessar.map(f => f.id);
        const [registros, ferias, configAlmoco] = await Promise.all([
            RegistroPonto.findAll({ where: { UserId: idsDosFuncionarios, timestamp: { [Op.between]: [dataInicioObj, dataFimObj] } } }),
            Ferias.findAll({ where: { UserId: idsDosFuncionarios } }),
            Configuracao.findOne({ where: { chave: 'duracao_almoco_minutos', EmpresaId: empresaId } })
        ]);
        const duracaoAlmoco = configAlmoco ? parseInt(configAlmoco.valor, 10) : 60;
        const relatorioAgrupado = [];
        for (const funcionario of funcionariosParaProcessar) {
            const dadosFuncionario = { id: funcionario.id, nome: funcionario.nome, semanas: [] };
            const registrosDoFunc = registros.filter(r => r.UserId === funcionario.id).sort((a,b) => new Date(a.timestamp) - new Date(b.timestamp));
            const feriasDoFunc = ferias.filter(f => f.UserId === funcionario.id);
            let semanaAtual = {};
            let dataAtualLoop = new Date(dataInicioObj);
            while (dataAtualLoop <= dataFimObj) {
                const diaDaSemana = dataAtualLoop.getDay();
                if (diaDaSemana > 0 && diaDaSemana < 6) {
                    const registrosDoDia = registrosDoFunc.filter(r => new Date(r.timestamp).toISOString().split('T')[0] === dataAtualLoop.toISOString().split('T')[0]);
                    const diaInfo = { data: new Date(dataAtualLoop), registros: registrosDoDia, horasTrabalhadas: '00h 00m', saldoHoras: '', observacao: '' };
                    const estaDeFerias = feriasDoFunc.some(f => { const inicio = new Date(f.dataInicio + 'T00:00:00-03:00'); const fim = new Date(f.dataFim + 'T23:59:59-03:00'); return dataAtualLoop >= inicio && dataAtualLoop <= fim; });
                    if (estaDeFerias) { diaInfo.observacao = 'Férias'; } else if (registrosDoDia.length === 0) { diaInfo.observacao = 'Falta'; }
                    if (registrosDoDia.length > 0) {
                        diaInfo.horasTrabalhadas = calcularHorasTrabalhadas(registrosDoDia);
                        if (diaInfo.horasTrabalhadas !== 'Jornada em aberto') {
                           const expediente = getHorarioExpediente(funcionario, dataAtualLoop);
                           const [hE, mE] = expediente.entrada.split(':').map(Number); const [hS, mS] = expediente.saida.split(':').map(Number);
                           const jornadaMin = ((hS - hE) * 60) + (mS - mE) - duracaoAlmoco;
                           const [hT, mT] = diaInfo.horasTrabalhadas.replace('h ', 'm').slice(0, -1).split('m');
                           const trabalhadoMin = (parseInt(hT) * 60) + parseInt(mT);
                           const saldoMin = trabalhadoMin - jornadaMin;
                           const sinal = saldoMin >= 0 ? '+' : '-';
                           const hSaldo = Math.floor(Math.abs(saldoMin) / 60).toString().padStart(2, '0');
                           const mSaldo = (Math.abs(saldoMin) % 60).toString().padStart(2, '0');
                           diaInfo.saldoHoras = `${sinal}${hSaldo}h ${mSaldo}m`;
                        }
                    }
                    const dias = ['domingo', 'segunda', 'terca', 'quarta', 'quinta', 'sexta'];
                    semanaAtual[dias[diaDaSemana]] = diaInfo;
                }
                if (diaDaSemana === 5) { if (Object.keys(semanaAtual).length > 0) dadosFuncionario.semanas.push(semanaAtual); semanaAtual = {}; }
                dataAtualLoop.setDate(dataAtualLoop.getDate() + 1);
            }
            if (Object.keys(semanaAtual).length > 0) dadosFuncionario.semanas.push(semanaAtual);
            relatorioAgrupado.push(dadosFuncionario);
        }

        // =================================================================
        // LÓGICA DE GERAÇÃO DE PDF ATUALIZADA
        // =================================================================
        const filePath = path.join(__dirname, 'views', 'espelho_ponto_pdf.ejs');
        const html = await ejs.renderFile(filePath, {
            relatorioAgrupado,
            dataInicio: dataInicioObj,
            dataFim: dataFimObj,
            empresa
        });

        // Bloco de inicialização do Puppeteer CORRIGIDO
        const browser = await puppeteer.launch({
            args: chromium.args,
            defaultViewport: chromium.defaultViewport,
            executablePath: await chromium.executablePath(),
            headless: chromium.headless,
        });

        const page = await browser.newPage();
        await page.setContent(html, { waitUntil: 'networkidle0' });

        const pdfBuffer = await page.pdf({ 
            format: 'A4', 
            printBackground: true,
            margin: { top: '20px', right: '20px', bottom: '20px', left: '20px' }
        });

        await browser.close();

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="espelho_ponto_${dataInicio}_a_${dataFim}.pdf"`);
        res.send(pdfBuffer);

    } catch (error) {
        console.error("Erro ao gerar PDF do espelho de ponto:", error);
        res.status(500).send('Ocorreu um erro ao gerar o PDF.');
    }
});

// ROTA PARA EXCLUIR REGISTRO DE PONTO ESPECÍFICO
app.post('/rh/registro/excluir/:id', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const registroId = req.params.id;
        const { empresaId } = req.session;

        // Primeiro, encontramos o registro para pegar o UserId
        const registro = await RegistroPonto.findOne({
            where: { id: registroId },
            include: { model: User, where: { EmpresaId: empresaId } } // Garante que o registro pertence a um usuário da empresa do RH
        });

        if (!registro) {
            return res.status(404).send('Registro de ponto não encontrado ou não pertence à sua empresa.');
        }

        // Agora, excluímos o registro
        await RegistroPonto.destroy({
            where: {
                id: registroId
            }
        });

        res.redirect('/rh/dashboard'); // Redireciona de volta para o dashboard
    } catch (error) {
        console.error("Erro ao excluir registro de ponto:", error);
        res.status(500).send('Ocorreu um erro ao tentar excluir o registro.');
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

// ROTA PARA MOSTRAR O FORMULÁRIO DE LANÇAMENTO MANUAL
app.get('/rh/registro-manual/:userId', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const funcionario = await User.findOne({
            where: { id: req.params.userId, EmpresaId: req.session.empresaId }
        });

        if (!funcionario) {
            return res.status(404).send('Funcionário não encontrado.');
        }

        res.render('registro_manual', { funcionario });
    } catch (error) {
        console.error("Erro ao abrir formulário de registro manual:", error);
        res.status(500).send("Ocorreu um erro.");
    }
});

// ROTA PARA SALVAR OS DADOS DO LANÇAMENTO MANUAL
app.post('/rh/registro-manual/:userId', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { userId } = req.params;
        const { data, entrada, saidaAlmoco, voltaAlmoco, saida } = req.body;

        if (!data) {
            return res.status(400).send("A data é obrigatória.");
        }

        const registrosParaCriar = [
            { tipo: 'Entrada', horario: entrada },
            { tipo: 'Saida Almoço', horario: saidaAlmoco },
            { tipo: 'Volta Almoço', horario: voltaAlmoco },
            { tipo: 'Saida', horario: saida }
        ];

        for (const registro of registrosParaCriar) {
            if (registro.horario) { // Apenas cria o registro se um horário foi fornecido
                await RegistroPonto.create({
                    UserId: userId,
                    tipo: registro.tipo,
                    timestamp: new Date(`${data}T${registro.horario}:00.000-03:00`) // Define o fuso horário
                });
            }
        }

        res.redirect('/rh/dashboard');

    } catch (error) {
        console.error("Erro ao salvar registro manual:", error);
        res.status(500).send("Ocorreu um erro ao salvar os registros.");
    }
});


// =================================================================
// FUNÇÕES E INICIALIZAÇÃO DO SERVIDOR
// =================================================================
async function iniciarSistema() {
    const adminEmail = process.env.ADMIN_EMAIL || 'rh@empresa.com';
    const adminSenha = process.env.ADMIN_SENHA || 'senha123';
    const [empresa, criada] = await Empresa.findOrCreate({
        where: { nome: 'Empresa Matriz (Padrão)' },
        defaults: { nome: 'Empresa Matriz (Padrão)' }
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

// --- FUNÇÃO ADICIONADA ---
// Cria a tabela de sessão se ela não existir
async function criarTabelaDeSessaoSeNaoExistir() {
    const query = `
    CREATE TABLE IF NOT EXISTS "session" (
      "sid" varchar NOT NULL COLLATE "default",
      "sess" json NOT NULL,
      "expire" timestamp(6) NOT NULL
    )
    WITH (OIDS=FALSE);
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint 
            WHERE conname = 'session_pkey'
        ) THEN
            ALTER TABLE "session" ADD CONSTRAINT "session_pkey" PRIMARY KEY ("sid");
        END IF;
    END;
    $$;
    CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
    `;
    try {
        await sequelize.query(query);
        console.log('Tabela de sessão verificada/criada com sucesso.');
    } catch (error) {
        console.error('Erro ao criar tabela de sessão:', error);
    }
}

// --- BLOCO DE INICIALIZAÇÃO ATUALIZADO ---
sequelize.sync().then(async () => {
    await iniciarSistema();
    await criarTabelaDeSessaoSeNaoExistir(); // <-- CHAMADA ADICIONADA
    app.listen(port, () => {
        console.log(`Servidor rodando em http://localhost:${port}`);
    });
}).catch(err => {
    console.error('Erro ao conectar ou sincronizar com o banco de dados:', err);
});