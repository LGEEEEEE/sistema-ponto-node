
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
const ejs = require('ejs');
const multer = require('multer'); // <--- NOVO
const fs = require('fs'); // <--- NOVO

// --- NOVO: Lógica Puppeteer Condicional ---
let puppeteer;
let chromiumArgs = {};
(async () => {
    if (process.env.NODE_ENV === 'production') {
        puppeteer = require('puppeteer-core');
        const chromium = require('@sparticuz/chromium');
        chromiumArgs = {
            args: chromium.args,
            executablePath: await chromium.executablePath(), // await aqui
            headless: chromium.headless,
        };
    } else {
        puppeteer = require('puppeteer');
    }
})(); // Auto-executa a função assíncrona para configurar puppeteer/chromium

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
    cnpj: { type: DataTypes.STRING, allowNull: true, unique: true },
    logoPath: { type: DataTypes.STRING, allowNull: true } // <--- NOVO CAMPO
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
// CONFIGURAÇÃO DO MULTER (UPLOAD DE LOGO)
// =================================================================
const logoStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = path.join(__dirname, 'public', 'logos');
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        const empresaId = req.session.empresaId;
        const extensao = path.extname(file.originalname);
        cb(null, `logo_empresa_${empresaId}_${Date.now()}${extensao}`);
    }
});

const uploadLogo = multer({
    storage: logoStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter: function (req, file, cb) {
        const tiposPermitidos = /jpeg|jpg|png|gif|webp/;
        const extensaoValida = tiposPermitidos.test(path.extname(file.originalname).toLowerCase());
        const mimeTypeValido = tiposPermitidos.test(file.mimetype);
        if (extensaoValida && mimeTypeValido) {
            return cb(null, true);
        } else {
            cb('Erro: Apenas arquivos de imagem (jpeg, jpg, png, gif, webp) são permitidos!');
        }
    }
}).single('logoEmpresa');


// =================================================================
// CONFIGURAÇÃO DO EXPRESS E MIDDLEWARES
// =================================================================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', true); // <--- MANTIDO (IMPORTANTE PARA PEGAR IP CORRETO)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public')); // <--- PARA SERVIR AS LOGOS

// --- CONFIGURAÇÃO DE SESSÃO INTELIGENTE ---
if (process.env.NODE_ENV === 'production') {
    const pool = new pg.Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });
    app.use(session({
        store: new PgStore({ pool: pool, tableName: 'session' }),
        secret: process.env.SESSION_SECRET || 'um-segredo-muito-forte-para-proteger-as-sessoes', // Use variável de ambiente
        resave: false,
        saveUninitialized: false,
        cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 dias
    }));
} else {
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
    // Busca usuário incluindo a Empresa para garantir que pertence à empresa correta (se necessário no futuro)
    const user = await User.findByPk(req.session.userId, { include: Empresa });
    if (user && user.role === 'rh') {
        // Garante que o empresaId da sessão corresponde ao usuário (segurança extra)
        if (user.EmpresaId === req.session.empresaId) {
            next();
        } else {
            console.warn(`Tentativa de acesso RH inválida: userId ${req.session.userId} com empresaId ${req.session.empresaId} diferente de ${user.EmpresaId}`);
            req.session.destroy(() => { // Destroi sessão suspeita
                res.status(403).send('Erro de sessão. Faça login novamente.');
            });
        }
    } else {
        res.status(403).send('Acesso negado. Você não tem permissão para acessar esta página.');
    }
}

// --- FUNÇÃO RESTRINGIR POR IP MODIFICADA ---
// --- FUNÇÃO RESTRINGIR POR IP (COM MENSAGEM AMIGÁVEL VIA RENDER) ---
async function restringirPorIP(req, res, next) {
    try {
        const empresaId = req.session.empresaId;
        if (!empresaId) {
            console.warn("Middleware restringirPorIP chamado sem empresaId na sessão.");
            // Redireciona para login com mensagem clara
            return res.redirect('/login?erro=sessao_invalida');
        }

        const configIp = await Configuracao.findOne({
            where: { chave: 'allowed_ips', EmpresaId: empresaId }
        });

        // Se não há configuração de IP ou está vazia, permite o acesso
        if (!configIp || !configIp.valor || configIp.valor.trim() === '') {
            return next();
        }

        const allowedIps = configIp.valor.split(',').map(ip => ip.trim()).filter(ip => ip); // Limpa e filtra IPs vazios
        const userIp = req.ip; // Confia no 'trust proxy'
        const devIps = ['::1', '127.0.0.1']; // IPs locais para desenvolvimento

        console.log(`Verificando IP: ${userIp} contra a lista [${allowedIps.join(', ')}] para Empresa ${empresaId}`); // Log para debug

        // Verifica se o IP está na lista OU se é IP de dev em ambiente não-produção
        if (allowedIps.includes(userIp) || (process.env.NODE_ENV !== 'production' && devIps.includes(userIp))) {
            next(); // IP Permitido
        } else {
            // IP não permitido
            console.warn(`ACESSO NEGADO POR IP: ${userIp} não permitido para Empresa ${empresaId}. Permitidos: [${allowedIps.join(', ')}]`);
            // Renderiza a página de erro amigável
            res.status(403).render('erro_generico', {
                titulo: 'Acesso Negado por Rede',
                mensagem: `Registro de ponto não permitido a partir desta localização (${userIp}). Por favor, utilize a rede configurada pela empresa. Se acredita que isso é um erro, contate o RH.`,
                voltarLink: '/dashboard' // Link para voltar ao dashboard do funcionário
            });
        }
    } catch (error) {
        console.error("Erro CRÍTICO ao verificar restrição de IP:", error);
        res.status(500).render('erro_generico', {
            titulo: 'Erro Interno',
            mensagem: 'Falha ao verificar permissão de acesso pela rede. Tente novamente mais tarde.',
            voltarLink: '/dashboard'
        });
    }
}
// --- FIM FUNÇÃO RESTRINGIR POR IP ---
// --- FIM DA MODIFICAÇÃO ---

function calcularHorasTrabalhadas(registros) {
    const registrosDoDia = registros || [];
    const entrada = registrosDoDia.find(r => r.tipo === 'Entrada');
    const saidaAlmoco = registrosDoDia.find(r => r.tipo === 'Saida Almoço');
    const voltaAlmoco = registrosDoDia.find(r => r.tipo === 'Volta Almoço');
    const saida = registrosDoDia.find(r => r.tipo === 'Saida');

    // Se só tem entrada, ou só entrada/saída almoço, não calcula
    if (!entrada) return '00h 00m';
    if (!saida && !voltaAlmoco && !saidaAlmoco) return 'Jornada em aberto'; // Só tem entrada

    let totalTrabalhadoMs = 0;
    const agora = new Date(); // Para cálculos parciais

    const entradaTimestamp = new Date(entrada.timestamp);

    if (saidaAlmoco) {
        // Trabalhou da entrada até a saída do almoço
        totalTrabalhadoMs += (new Date(saidaAlmoco.timestamp) - entradaTimestamp);
        if (voltaAlmoco) {
            // Se já voltou do almoço
            const voltaAlmocoTimestamp = new Date(voltaAlmoco.timestamp);
            if (saida) {
                // Se já saiu no fim do dia
                totalTrabalhadoMs += (new Date(saida.timestamp) - voltaAlmocoTimestamp);
            } else {
                // Se voltou do almoço mas ainda não saiu (calcula até agora)
                totalTrabalhadoMs += (agora - voltaAlmocoTimestamp);
                return formatarMsParaHorasMinutos(totalTrabalhadoMs) + ' (parcial)';
            }
        }
        // Se saiu para almoço mas não voltou nem saiu, retorna o que trabalhou até o almoço
        // Não adiciona "(parcial)" pois a jornada está interrompida
        return formatarMsParaHorasMinutos(totalTrabalhadoMs);

    } else if (saida) {
        // Se não teve almoço mas já saiu
        totalTrabalhadoMs = (new Date(saida.timestamp) - entradaTimestamp);
    } else {
        // Se só tem entrada (e talvez saída sem almoço), calcula até agora
        totalTrabalhadoMs = (agora - entradaTimestamp);
        return formatarMsParaHorasMinutos(totalTrabalhadoMs) + ' (parcial)';
    }

    return formatarMsParaHorasMinutos(totalTrabalhadoMs);
}

// Função auxiliar para formatar milissegundos
function formatarMsParaHorasMinutos(ms) {
    if (ms <= 0) return '00h 00m';
    const horas = Math.floor(ms / 3600000);
    const minutos = Math.floor((ms % 3600000) / 60000);
    return `${horas.toString().padStart(2, '0')}h ${minutos.toString().padStart(2, '0')}m`;
}


function getHorarioExpediente(usuario, data) {
    const horarioPadrao = { entrada: '09:00:00', saida: '18:00:00' };
    const horario = {
        entrada: usuario.horarioEntrada || horarioPadrao.entrada,
        saida: usuario.horarioSaida || horarioPadrao.saida
    };

    // Verifica se a data é válida
    if (!(data instanceof Date && !isNaN(data))) {
        console.warn("getHorarioExpediente recebeu data inválida:", data);
        return horario; // Retorna o horário padrão ou do usuário sem ajuste
    }


    // Ajuste de sexta-feira (getDay() === 5)
    if (data.getDay() === 5) {
        // Subtrai uma hora da entrada
        try {
            const [hE, mE, sE] = horario.entrada.split(':').map(Number);
            const dataEntrada = new Date();
            dataEntrada.setHours(hE, mE, sE, 0);
            dataEntrada.setHours(dataEntrada.getHours() - 1);
            horario.entrada = dataEntrada.toTimeString().split(' ')[0];
        } catch (e) {
            console.error("Erro ao ajustar horário de entrada para sexta:", e, "Horário original:", horario.entrada);
            // Mantém o horário original se houver erro
        }

        // Subtrai uma hora da saída
        try {
            const [hS, mS, sS] = horario.saida.split(':').map(Number);
            const dataSaida = new Date();
            dataSaida.setHours(hS, mS, sS, 0);
            dataSaida.setHours(dataSaida.getHours() - 1);
            horario.saida = dataSaida.toTimeString().split(' ')[0];
        } catch (e) {
            console.error("Erro ao ajustar horário de saída para sexta:", e, "Horário original:", horario.saida);
            // Mantém o horário original se houver erro
        }
    }
    return horario;
}


// =================================================================
// ROTAS DA APLICAÇÃO
// =================================================================

// --- Rota de Cadastro de Empresa ---
// MODIFICADA para enviar o IP
app.get('/empresa/cadastrar', (req, res) => {
    const userIp = req.ip;
    res.render('empresa_cadastro', { userIp: userIp });
});

// MODIFICADA para salvar o IP
app.post('/empresa/cadastrar', async (req, res) => {
    const { nomeEmpresa, cnpj, nomeAdmin, emailAdmin, senhaAdmin, allowedIps } = req.body;

    // Validação básica do IP (evita salvar lixo, mas não valida formato 100%)
    if (!allowedIps || allowedIps.trim() === '') {
        // Renderiza o form de novo com mensagem de erro e dados preenchidos
        return res.render('empresa_cadastro', {
            userIp: req.ip, // Reenvia o IP do usuário
            error: 'O campo de IPs Permitidos é obrigatório.',
            formData: req.body // Reenvia os dados para preencher o form
        });
    }

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

        // Salva o IP na tabela de Configuração
        await Configuracao.create({
            chave: 'allowed_ips',
            valor: allowedIps,
            EmpresaId: novaEmpresa.id
        }, { transaction: t });

        // Salva uma configuração de almoço padrão
        await Configuracao.create({
            chave: 'duracao_almoco_minutos',
            valor: '60',
            EmpresaId: novaEmpresa.id
        }, { transaction: t });

        await t.commit();
        res.redirect('/rh/login');
    } catch (error) {
        await t.rollback();
        console.error("Erro no cadastro de empresa:", error);
        // Verifica se é erro de unicidade (email ou CNPJ)
        let errorMessage = 'Erro ao cadastrar nova empresa.';
        if (error.name === 'SequelizeUniqueConstraintError') {
            errorMessage = 'Erro: O Email ou CNPJ informado já está em uso.';
        }
        // Renderiza o form novamente com a mensagem de erro
        res.render('empresa_cadastro', {
            userIp: req.ip,
            error: errorMessage,
            formData: req.body // Reenvia os dados
        });
    }
});
// --- FIM MODIFICAÇÃO CADASTRO EMPRESA ---


// --- Rotas de Autenticação Funcionário ---
app.get('/cadastro', checarAutenticacao, checarAutorizacaoRH, (req, res) => {
    res.render('cadastro');
});

app.post('/cadastro', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    const { nome, email, senha } = req.body;
    try {
        const senhaHash = await bcrypt.hash(senha, 10);
        await User.create({
            nome, email, senha: senhaHash,
            EmpresaId: req.session.empresaId // Pega o ID da empresa do RH logado
        });
        res.redirect('/rh/dashboard?msg=func_cadastrado'); // Adiciona msg de sucesso
    } catch (error) {
        console.error("Erro no cadastro de funcionário:", error);
        let errorMessage = 'Erro ao cadastrar funcionário.';
        if (error.name === 'SequelizeUniqueConstraintError') {
            errorMessage = 'Erro: O Email informado já está em uso.';
        }
        // Idealmente, redirecionar de volta com erro, mas por simplicidade:
        res.status(500).send(errorMessage);
        // Ou renderizar a view 'cadastro' com a mensagem de erro:
        // res.render('cadastro', { error: errorMessage });
    }
});

app.get('/login', (req, res) => {
    // Passa a query string para a view poder exibir mensagens (ex: erro=sessao_expirada)
    res.render('login', { query: req.query });
});

app.post('/login', async (req, res) => {
    const { email, senha } = req.body;
    try {
        const user = await User.findOne({ where: { email, role: 'funcionario' } });
        if (user && await bcrypt.compare(senha, user.senha)) {
            req.session.userId = user.id;
            req.session.userRole = user.role;
            req.session.empresaId = user.EmpresaId;
            res.redirect('/dashboard');
        } else {
            res.render('login', { error: 'Email ou senha incorretos.', query: {} });
        }
    } catch (error) {
        console.error("Erro no login do funcionário:", error);
        res.render('login', { error: 'Ocorreu um erro interno. Tente novamente.', query: {} });
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("Erro ao destruir sessão:", err);
            // Mesmo com erro, tenta redirecionar
            return res.redirect('/login?erro=logout_falhou');
        }
        res.clearCookie('connect.sid'); // Nome padrão do cookie de sessão do Express
        res.redirect('/login');
    });
});

// --- Rota Meu Relatório (Funcionário) ---
app.get('/meu-relatorio', checarAutenticacao, async (req, res) => {
    try {
        const { userId, empresaId } = req.session;
        const { dataInicio, dataFim } = req.query;

        const hoje = new Date();
        // Define o início do mês atual como padrão se não houver dataInicio
        const inicioMes = new Date(hoje.getFullYear(), hoje.getMonth(), 1).toISOString().split('T')[0];
        // Define o dia de hoje como padrão se não houver dataFim
        const hojeStr = hoje.toISOString().split('T')[0];

        const dataInicioSelecionada = dataInicio || inicioMes;
        const dataFimSelecionada = dataFim || hojeStr;


        const funcionario = await User.findByPk(userId);
        if (!funcionario) return res.status(404).send("Funcionário não encontrado.");

        // A lógica de busca e agrupamento de dados
        const dataInicioObj = new Date(`${dataInicioSelecionada}T00:00:00-03:00`);
        const dataFimObj = new Date(`${dataFimSelecionada}T23:59:59-03:00`);

        if (isNaN(dataInicioObj) || isNaN(dataFimObj)) {
            return res.render('meu_relatorio', {
                relatorioAgrupado: null,
                dataInicioSelecionada: hojeStr,
                dataFimSelecionada: hojeStr,
                error: "Datas inválidas fornecidas."
            });
        }


        const [registros, ferias, configAlmoco] = await Promise.all([
            RegistroPonto.findAll({ where: { UserId: userId, timestamp: { [Op.between]: [dataInicioObj, dataFimObj] } }, order: [['timestamp', 'ASC']] }),
            Ferias.findAll({ where: { UserId: userId } }), // Busca todas as férias do usuário para checar
            Configuracao.findOne({ where: { chave: 'duracao_almoco_minutos', EmpresaId: empresaId } })
        ]);

        const duracaoAlmoco = configAlmoco ? parseInt(configAlmoco.valor, 10) : 60;
        // const registrosDoFunc = registros; // Já estão ordenados

        const dadosFuncionario = { semanas: [] };
        let semanaAtual = {};
        let dataAtualLoop = new Date(dataInicioObj); // Começa do início selecionado

        while (dataAtualLoop <= dataFimObj) {
            const diaDaSemana = dataAtualLoop.getDay(); // 0 = Domingo, 1 = Segunda, ..., 6 = Sábado
            const diaString = dataAtualLoop.toISOString().split('T')[0];

            // Considera apenas dias úteis (Segunda a Sexta)
            if (diaDaSemana >= 1 && diaDaSemana <= 5) {
                const registrosDoDia = registros.filter(r => new Date(r.timestamp).toISOString().split('T')[0] === diaString);
                const diaInfo = {
                    data: new Date(dataAtualLoop), // Guarda o objeto Date
                    registros: registrosDoDia,
                    horasTrabalhadas: '00h 00m',
                    saldoHoras: '',
                    observacao: ''
                };

                // Verifica se está de férias neste dia
                const estaDeFerias = ferias.some(f => {
                    // Comparação segura de datas (considerando apenas a data, não a hora)
                    const inicioF = new Date(f.dataInicio + 'T00:00:00-03:00');
                    const fimF = new Date(f.dataFim + 'T23:59:59-03:00');
                    // Normaliza dataAtualLoop para início do dia para comparação
                    const diaAtualNormalizado = new Date(diaString + 'T00:00:00-03:00');
                    return diaAtualNormalizado >= inicioF && diaAtualNormalizado <= fimF;
                });

                if (estaDeFerias) {
                    diaInfo.observacao = 'Férias';
                    diaInfo.horasTrabalhadas = '-'; // Ou 'Férias'
                    diaInfo.saldoHoras = '-';
                } else if (registrosDoDia.length === 0) {
                    diaInfo.observacao = 'Falta';
                    diaInfo.horasTrabalhadas = 'Falta';
                    diaInfo.saldoHoras = '-'; // Saldo negativo da jornada
                    // Calcula o saldo negativo da falta (opcional)
                    try {
                        const expediente = getHorarioExpediente(funcionario, dataAtualLoop);
                        const [hE, mE] = expediente.entrada.split(':').map(Number);
                        const [hS, mS] = expediente.saida.split(':').map(Number);
                        const jornadaMin = ((hS - hE) * 60) + (mS - mE) - duracaoAlmoco;
                        const hSaldo = Math.floor(jornadaMin / 60).toString().padStart(2, '0');
                        const mSaldo = (jornadaMin % 60).toString().padStart(2, '0');
                        diaInfo.saldoHoras = `-${hSaldo}h ${mSaldo}m`;
                    } catch { diaInfo.saldoHoras = '-'; } // Fallback
                } else {
                    diaInfo.horasTrabalhadas = calcularHorasTrabalhadas(registrosDoDia);
                    // Só calcula saldo se a jornada não estiver aberta ou parcial
                    if (!diaInfo.horasTrabalhadas.includes('Jornada em aberto') && !diaInfo.horasTrabalhadas.includes('(parcial)')) {
                        try {
                            const expediente = getHorarioExpediente(funcionario, dataAtualLoop);
                            const [hE, mE] = expediente.entrada.split(':').map(Number);
                            const [hS, mS] = expediente.saida.split(':').map(Number);
                            const jornadaMin = ((hS - hE) * 60) + (mS - mE) - duracaoAlmoco;

                            // Extrai horas e minutos trabalhados
                            const match = diaInfo.horasTrabalhadas.match(/(\d{2})h (\d{2})m/);
                            if (match) {
                                const hT = parseInt(match[1], 10);
                                const mT = parseInt(match[2], 10);
                                const trabalhadoMin = (hT * 60) + mT;
                                const saldoMin = trabalhadoMin - jornadaMin;

                                const sinal = saldoMin >= 0 ? '+' : '-';
                                const hSaldo = Math.floor(Math.abs(saldoMin) / 60).toString().padStart(2, '0');
                                const mSaldo = (Math.abs(saldoMin) % 60).toString().padStart(2, '0');
                                diaInfo.saldoHoras = `${sinal}${hSaldo}h ${mSaldo}m`;
                            } else {
                                diaInfo.saldoHoras = 'Erro Calc'; // Indica erro na extração
                            }
                        } catch (calcError) {
                            console.error("Erro ao calcular saldo de horas:", calcError, "Dia:", diaString, "Horas:", diaInfo.horasTrabalhadas);
                            diaInfo.saldoHoras = 'Erro Calc';
                        }
                    } else {
                        diaInfo.saldoHoras = '-'; // Jornada não fechada
                    }
                }

                // Adiciona ao objeto da semana atual usando a chave correta
                const dias = ['domingo', 'segunda', 'terca', 'quarta', 'quinta', 'sexta', 'sabado'];
                semanaAtual[dias[diaDaSemana]] = diaInfo;
            }

            // Se for Sexta-feira OU o último dia do período, fecha a semana
            if (diaDaSemana === 5 || dataAtualLoop.getTime() === dataFimObj.getTime() || dataAtualLoop > dataFimObj) {
                if (Object.keys(semanaAtual).length > 0) {
                    // Adiciona uma propriedade de data de início da semana para ordenação
                    const primeiraDataDaSemana = Object.values(semanaAtual)[0].data;
                    semanaAtual.dataInicioSemana = primeiraDataDaSemana;
                    dadosFuncionario.semanas.push(semanaAtual);
                }
                semanaAtual = {}; // Começa uma nova semana
            }

            // Incrementa o dia
            dataAtualLoop.setDate(dataAtualLoop.getDate() + 1);
        }

        // Ordena as semanas pela data de início
        dadosFuncionario.semanas.sort((a, b) => a.dataInicioSemana - b.dataInicioSemana);

        res.render('meu_relatorio', {
            relatorioAgrupado: dadosFuncionario,
            dataInicioSelecionada: dataInicioSelecionada,
            dataFimSelecionada: dataFimSelecionada
        });

    } catch (error) {
        console.error("Erro ao gerar relatório do funcionário:", error);
        res.status(500).render('meu_relatorio', {
            relatorioAgrupado: null,
            dataInicioSelecionada: dataInicio || new Date().toISOString().split('T')[0], // Fallback
            dataFimSelecionada: dataFim || new Date().toISOString().split('T')[0],     // Fallback
            error: "Ocorreu um erro ao gerar o relatório. Tente novamente."
        });
    }
});


// --- Rotas de Autenticação do RH ---
app.get('/rh/login', (req, res) => {
    res.render('rh_login');
});

app.post('/rh/login', async (req, res) => {
    const { email, senha } = req.body;
    try {
        const user = await User.findOne({ where: { email, role: 'rh' } });
        if (user && await bcrypt.compare(senha, user.senha)) {
            req.session.userId = user.id;
            req.session.userRole = user.role;
            req.session.empresaId = user.EmpresaId; // Guarda o ID da empresa do RH na sessão
            res.redirect('/rh/dashboard');
        } else {
            res.render('rh_login', { error: 'Credenciais inválidas ou sem permissão de acesso.' });
        }
    } catch (error) {
        console.error("Erro no login do RH:", error);
        res.render('rh_login', { error: 'Ocorreu um erro interno. Tente novamente.' });
    }
});

// --- Rotas Principais (Dashboard Funcionário) ---
app.get('/dashboard', checarAutenticacao, async (req, res) => {
    try {
        const user = await User.findByPk(req.session.userId);
        if (!user) {
            // Se o usuário não for encontrado no DB (pode ter sido excluído), força logout
            return req.session.destroy(() => {
                res.redirect('/login?erro=usuario_invalido');
            });
        }
        const hoje = new Date();
        const inicioDoDia = new Date(hoje.getFullYear(), hoje.getMonth(), hoje.getDate(), 0, 0, 0, 0); // Zera hora pro início do dia local
        const fimDoDia = new Date(hoje.getFullYear(), hoje.getMonth(), hoje.getDate(), 23, 59, 59, 999); // Fim do dia local

        const registros = await RegistroPonto.findAll({
            where: {
                UserId: req.session.userId,
                timestamp: {
                    [Op.between]: [inicioDoDia, fimDoDia]
                }
            },
            order: [['timestamp', 'ASC']]
        });
        res.render('dashboard', { user, registros, query: req.query });
    } catch (error) {
        console.error("Erro ao carregar dashboard:", error);
        // Tenta renderizar com erro ou redireciona
        res.status(500).send("Erro ao carregar dashboard. Tente recarregar a página.");
    }
});

app.post('/registrar', checarAutenticacao, restringirPorIP, async (req, res) => {
    try {
        const userId = req.session.userId;
        const hoje = new Date();
        const inicioDoDia = new Date(hoje.getFullYear(), hoje.getMonth(), hoje.getDate(), 0, 0, 0, 0);
        const fimDoDia = new Date(hoje.getFullYear(), hoje.getMonth(), hoje.getDate(), 23, 59, 59, 999);

        const registrosDoDia = await RegistroPonto.findAll({
            where: {
                UserId: userId,
                timestamp: { [Op.between]: [inicioDoDia, fimDoDia] }
            },
            order: [['timestamp', 'ASC']]
        });

        let tipoDeBatida = '';
        switch (registrosDoDia.length) {
            case 0: tipoDeBatida = 'Entrada'; break;
            case 1: tipoDeBatida = 'Saida Almoço'; break;
            case 2: tipoDeBatida = 'Volta Almoço'; break;
            case 3: tipoDeBatida = 'Saida'; break;
            default: return res.redirect('/dashboard?mensagem=ciclo_finalizado');
        }
        await RegistroPonto.create({ UserId: userId, tipo: tipoDeBatida, timestamp: new Date() }); // Garante timestamp atual
        res.redirect('/dashboard?msg=ponto_registrado');
    } catch (error) {
        console.error("Erro ao registrar ponto:", error);
        res.status(500).send('Ocorreu um erro ao registrar o ponto.');
    }
});

// --- Rotas do RH ---

// --- NOVAS ROTAS PARA GERENCIAR EMPRESA ---
app.get('/rh/empresa/editar', checarAutenticacao, checarAutorizacaoRH, (req, res) => {
    res.render('editar_empresa'); // Renderiza a nova view
});

// ROTA PARA OBTER DADOS DA EMPRESA (MODIFICADA PARA INCLUIR IPs)
app.get('/rh/empresa/dados', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const empresaId = req.session.empresaId;
        // Busca a empresa E a configuração de IP em paralelo
        const [empresa, configIp] = await Promise.all([
            Empresa.findByPk(empresaId, {
                attributes: ['nome', 'cnpj', 'logoPath']
            }),
            Configuracao.findOne({
                where: { chave: 'allowed_ips', EmpresaId: empresaId },
                attributes: ['valor'] // Pega só o valor (os IPs)
            })
        ]);

        if (!empresa) {
            return res.status(404).json({ success: false, message: 'Empresa não encontrada.' });
        }
        res.json({
            success: true,
            empresa: {
                nome: empresa.nome,
                cnpj: empresa.cnpj,
                logoPath: empresa.logoPath,
                // Adiciona os IPs (ou string vazia se não encontrado)
                allowedIps: configIp ? configIp.valor : ''
            }
        });
    } catch (error) {
        console.error("Erro ao buscar dados da empresa:", error);
        res.status(500).json({ success: false, message: 'Erro ao carregar dados.' });
    }
});

app.post('/rh/empresa/logo', checarAutenticacao, checarAutorizacaoRH, (req, res) => {
    uploadLogo(req, res, async (err) => {
        if (err) {
            console.error("Erro no upload:", err);
            if (err instanceof multer.MulterError || err.startsWith('Erro:')) {
                return res.status(400).json({ success: false, message: err.message || err });
            }
            return res.status(500).json({ success: false, message: 'Erro interno no upload.' });
        }
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Nenhum arquivo enviado.' });
        }

        try {
            const empresaId = req.session.empresaId;
            // Caminho relativo para salvar no BD e usar no src da img
            const logoPathRelativo = `/logos/${req.file.filename}`;

            const empresa = await Empresa.findByPk(empresaId);
            if (empresa && empresa.logoPath) {
                const caminhoAntigo = path.join(__dirname, 'public', empresa.logoPath);
                // Verifica se o caminho antigo é diferente do novo antes de deletar
                // (evita erro se o usuário reenviar a mesma imagem rapidamente)
                if (fs.existsSync(caminhoAntigo) && empresa.logoPath !== logoPathRelativo) {
                    try {
                        fs.unlinkSync(caminhoAntigo);
                    } catch (unlinkErr) {
                        console.error("Erro ao deletar logo antiga:", unlinkErr);
                        // Continua mesmo se não conseguir deletar o antigo
                    }
                }
            }

            await Empresa.update({ logoPath: logoPathRelativo }, { where: { id: empresaId } });

            res.json({ success: true, message: 'Logo atualizada!', filePath: logoPathRelativo });

        } catch (dbError) {
            console.error("Erro ao salvar path no BD:", dbError);
            const caminhoNovo = path.join(__dirname, 'public', 'logos', req.file.filename);
            if (fs.existsSync(caminhoNovo)) {
                try {
                    fs.unlinkSync(caminhoNovo);
                } catch (unlinkErr) {
                    console.error("Erro ao deletar logo após falha no BD:", unlinkErr);
                }
            }
            res.status(500).json({ success: false, message: 'Erro ao salvar informações no banco de dados.' });
        }
    });
});

// ROTA PARA EDITAR DADOS (Nome, CNPJ e IPs) - MODIFICADA
app.post('/rh/empresa/editar', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    // O middleware express.json() já está global, não precisa aqui
    try {
        // Adiciona allowedIps na desestruturação
        const { nome, cnpj, allowedIps } = req.body;
        const empresaId = req.session.empresaId;

        if (!nome || nome.trim() === '') {
            return res.status(400).json({ success: false, message: 'O nome da empresa não pode ser vazio.' });
        }
        // Validação básica de IPs (não valida formato, apenas se existe)
        if (allowedIps === undefined || allowedIps === null) {
            // Considera string vazia como válida (para desativar restrição)
            // Se fosse obrigatório, a validação seria diferente
            // return res.status(400).json({ success: false, message: 'O campo IPs Permitidos deve ser enviado.' });
        }


        // Usa transação para garantir atomicidade
        const t = await sequelize.transaction();
        try {
            // Atualiza nome e CNPJ na tabela Empresa
            await Empresa.update({ nome, cnpj }, { where: { id: empresaId }, transaction: t });

            // Atualiza (ou cria) a configuração de IPs na tabela Configuracao
            await Configuracao.upsert({
                chave: 'allowed_ips',
                valor: (allowedIps || '').trim(), // Usa string vazia se for null/undefined e remove espaços
                EmpresaId: empresaId
            }, { transaction: t });

            await t.commit(); // Confirma as alterações
            res.json({ success: true, message: 'Dados atualizados com sucesso!' });

        } catch (innerError) {
            await t.rollback(); // Desfaz alterações se algo der errado
            throw innerError; // Re-lança o erro para o catch externo
        }

    } catch (error) {
        console.error("Erro ao editar dados da empresa:", error);
        let message = 'Erro ao salvar alterações.';
        if (error.name === 'SequelizeUniqueConstraintError' && error.fields && error.fields.cnpj) {
            message = 'Erro: Este CNPJ já está cadastrado por outra empresa.';
        }
        res.status(500).json({ success: false, message: message });
    }
});
// --- FIM ROTAS EMPRESA ---


// ROTA PARA EXCLUIR FUNCIONÁRIO
app.post('/rh/funcionario/excluir/:id', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        const funcionarioId = req.params.id;

        // Verifica se o ID é válido
        if (!funcionarioId || isNaN(parseInt(funcionarioId))) {
            return res.status(400).send('ID de funcionário inválido.');
        }


        // Deleta em cascata (ou define ON DELETE CASCADE no DB) - CUIDADO!
        // Alternativa: Buscar e deletar registros associados primeiro
        await RegistroPonto.destroy({ where: { UserId: funcionarioId } });
        await Ferias.destroy({ where: { UserId: funcionarioId } });

        const deletedCount = await User.destroy({
            where: {
                id: funcionarioId,
                EmpresaId: empresaId,
                role: 'funcionario' // Garante que não está excluindo um RH
            }
        });

        if (deletedCount > 0) {
            res.redirect('/rh/dashboard?msg=func_excluido');
        } else {
            // Pode acontecer se o funcionário não existir ou não pertencer à empresa
            res.status(404).send('Funcionário não encontrado ou não pertence à sua empresa.');
        }

    } catch (error) {
        console.error("Erro ao excluir funcionário:", error);
        res.status(500).send('Ocorreu um erro ao tentar excluir o funcionário.');
    }
});

// ROTA PARA MOSTRAR A PÁGINA DE EDIÇÃO DE FUNCIONÁRIO
app.get('/rh/funcionario/editar/:id', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        const funcionarioId = req.params.id;

        if (!funcionarioId || isNaN(parseInt(funcionarioId))) {
            return res.status(400).send('ID de funcionário inválido.');
        }


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

// ROTA PARA SALVAR OS DADOS EDITADOS DO FUNCIONÁRIO
app.post('/rh/funcionario/editar/:id', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        const funcionarioId = req.params.id;
        const { nome, email, senha } = req.body;

        if (!funcionarioId || isNaN(parseInt(funcionarioId))) {
            return res.status(400).send('ID de funcionário inválido.');
        }
        if (!nome || !email) {
            // Recarrega a página de edição com erro
            const funcionario = await User.findByPk(funcionarioId); // Busca de novo para reenviar
            return res.render('editar_funcionario', {
                funcionario: funcionario,
                error: 'Nome e Email são obrigatórios.'
            });
        }


        const dadosParaAtualizar = { nome, email };

        // Se uma nova senha foi fornecida E NÃO ESTÁ VAZIA, criptografa
        if (senha && senha.trim() !== '') {
            dadosParaAtualizar.senha = await bcrypt.hash(senha, 10);
        }

        const [updatedCount] = await User.update(dadosParaAtualizar, {
            where: {
                id: funcionarioId,
                EmpresaId: empresaId,
                role: 'funcionario' // Segurança extra
            }
        });

        if (updatedCount > 0) {
            res.redirect('/rh/dashboard?msg=func_editado');
        } else {
            // Pode acontecer se o funcionário não foi encontrado com os critérios
            res.status(404).send('Funcionário não encontrado para atualização.');
        }

    } catch (error) {
        console.error("Erro ao salvar edição do funcionário:", error);
        let errorMessage = 'Ocorreu um erro ao salvar as alterações.';
        if (error.name === 'SequelizeUniqueConstraintError') {
            errorMessage = 'Erro: O Email informado já está em uso por outro usuário.';
        }
        // Recarrega a página de edição com erro
        const funcionarioId = req.params.id;
        try {
            const funcionario = await User.findByPk(funcionarioId);
            res.render('editar_funcionario', {
                funcionario: funcionario, // Reenvia dados atuais (sem a senha)
                error: errorMessage
            });
        } catch (findError) {
            res.status(500).send(errorMessage + ' (Erro ao recarregar dados do funcionário)');
        }
    }
});

// DASHBOARD DO RH
app.get('/rh/dashboard', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        // Busca a empresa junto para ter o nome no dashboard (opcional)
        // const empresa = await Empresa.findByPk(empresaId);
        const todosUsuarios = await User.findAll({ where: { role: 'funcionario', EmpresaId: empresaId }, order: [['nome', 'ASC']] });

        const hoje = new Date();
        const inicioDoDia = new Date(hoje.getFullYear(), hoje.getMonth(), hoje.getDate(), 0, 0, 0, 0);
        const fimDoDia = new Date(hoje.getFullYear(), hoje.getMonth(), hoje.getDate(), 23, 59, 59, 999);

        const idsDosFuncionarios = todosUsuarios.map(u => u.id);

        // Otimização: Busca registros apenas se houver funcionários
        let registrosDeHoje = [];
        let todasFerias = [];
        if (idsDosFuncionarios.length > 0) {
            [registrosDeHoje, todasFerias] = await Promise.all([
                RegistroPonto.findAll({
                    where: {
                        UserId: idsDosFuncionarios,
                        timestamp: { [Op.between]: [inicioDoDia, fimDoDia] }
                    },
                    include: { model: User, attributes: ['id', 'nome'] }, // Inclui User só pra debug se precisar
                    order: [['UserId', 'ASC'], ['timestamp', 'ASC']]
                }),
                Ferias.findAll({
                    where: { UserId: idsDosFuncionarios },
                    order: [['dataInicio', 'DESC']]
                })
            ]);
        }

        const configAlmoco = await Configuracao.findOne({ where: { chave: 'duracao_almoco_minutos', EmpresaId: empresaId } });
        const duracaoAlmocoAtual = configAlmoco ? configAlmoco.valor : '60';

        // Agrupa dados por usuário
        const registrosPorUsuario = {};
        registrosDeHoje.forEach(r => { (registrosPorUsuario[r.UserId] = registrosPorUsuario[r.UserId] || []).push(r); });

        const feriasPorUsuario = {};
        todasFerias.forEach(f => { (feriasPorUsuario[f.UserId] = feriasPorUsuario[f.UserId] || []).push(f); });

        const horasPorUsuario = {}, expedienteDoDiaPorUsuario = {};
        todosUsuarios.forEach(u => {
            horasPorUsuario[u.id] = calcularHorasTrabalhadas(registrosPorUsuario[u.id]);
            expedienteDoDiaPorUsuario[u.id] = getHorarioExpediente(u, hoje); // Passa a data 'hoje'
        });

        res.render('rh_dashboard', {
            usuarios: todosUsuarios,
            registros: registrosPorUsuario,
            horas: horasPorUsuario,
            expedientes: expedienteDoDiaPorUsuario,
            ferias: feriasPorUsuario,
            duracaoAlmocoAtual,
            // empresaNome: empresa ? empresa.nome : 'Empresa', // Opcional
            query: req.query // Passa query para exibir mensagens de sucesso/erro
        });
    } catch (error) {
        console.error("Erro na dashboard do RH:", error);
        res.status(500).send('Ocorreu um erro ao carregar a página do RH.');
    }
});

// DEFINIR HORÁRIO PADRÃO DO FUNCIONÁRIO
app.post('/rh/definir-horario/:userId', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { horarioEntrada, horarioSaida } = req.body;
        const userId = req.params.userId;
        const { empresaId } = req.session;

        // Validações
        if (!userId || isNaN(parseInt(userId))) return res.status(400).send('ID inválido.');
        if (!horarioEntrada || !horarioSaida) return res.status(400).send('Horários de entrada e saída são obrigatórios.');
        // Poderia validar o formato do tempo aqui se necessário

        await User.update(
            { horarioEntrada, horarioSaida },
            { where: { id: userId, EmpresaId: empresaId, role: 'funcionario' } }
        );
        res.redirect('/rh/dashboard?msg=horario_definido');
    } catch (error) {
        console.error("Erro ao definir horário:", error);
        res.status(500).send('Ocorreu um erro ao definir o horário.');
    }
});

// AGENDAR FÉRIAS
app.post('/rh/ferias/agendar', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { funcionarioId, dataInicio, dataFim } = req.body;
        const { empresaId } = req.session;

        // Validações
        if (!funcionarioId || isNaN(parseInt(funcionarioId))) return res.status(400).send('ID de funcionário inválido.');
        if (!dataInicio || !dataFim) return res.status(400).send('Datas de início e fim são obrigatórias.');

        const inicio = new Date(dataInicio + 'T00:00:00-03:00'); // Adiciona fuso
        const fim = new Date(dataFim + 'T00:00:00-03:00');    // Adiciona fuso

        if (isNaN(inicio) || isNaN(fim) || fim < inicio) {
            return res.status(400).send('Datas inválidas ou data final anterior à inicial.');
        }

        // Verifica se funcionário pertence à empresa
        const funcionario = await User.findOne({ where: { id: funcionarioId, EmpresaId: empresaId, role: 'funcionario' } });
        if (!funcionario) {
            return res.status(404).send('Funcionário não encontrado ou não pertence à sua empresa.');
        }

        // TO DO: Adicionar verificação de sobreposição de férias se necessário

        await Ferias.create({
            dataInicio: dataInicio, // Salva como YYYY-MM-DD
            dataFim: dataFim,       // Salva como YYYY-MM-DD
            UserId: funcionarioId
        });
        res.redirect('/rh/dashboard?msg=ferias_agendadas');
    } catch (error) {
        console.error("Erro ao agendar férias:", error);
        res.status(500).send('Ocorreu um erro ao agendar as férias.');
    }
});

// SALVAR CONFIGURAÇÕES GERAIS (TEMPO ALMOÇO)
app.post('/rh/configuracoes', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    // Adiciona middleware para parsear JSON se ainda não tiver globalmente
    // app.use(express.json()); // <--- ADICIONE NO TOPO SE NÃO TIVER
    try {
        const { duracaoAlmocoMinutos } = req.body;
        const { empresaId } = req.session;

        // Validação
        const duracao = parseInt(duracaoAlmocoMinutos, 10);
        if (isNaN(duracao) || duracao < 0) {
            return res.status(400).send('Duração do almoço inválida. Deve ser um número não negativo.');
        }


        // Upsert: Atualiza se existir, cria se não existir
        await Configuracao.upsert({
            chave: 'duracao_almoco_minutos',
            valor: duracao.toString(), // Salva como string
            EmpresaId: empresaId
        });
        res.redirect('/rh/dashboard?msg=config_salva');
    } catch (error) {
        console.error("Erro ao salvar configuração:", error);
        res.status(500).send('Ocorreu um erro ao salvar a configuração.');
    }
});

// RELATÓRIO DE FALTAS (TELA)
app.get('/rh/relatorios', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    // ... (código existente sem alterações significativas, exceto talvez datas padrão)
    try {
        const { empresaId } = req.session;
        const { dataInicio, dataFim, funcionarioId } = req.query;

        const hoje = new Date();
        const inicioMes = new Date(hoje.getFullYear(), hoje.getMonth(), 1).toISOString().split('T')[0];
        const hojeStr = hoje.toISOString().split('T')[0];

        const inicio = dataInicio || inicioMes;
        const fim = dataFim || hojeStr;
        const funcIdSelecionado = funcionarioId || 'todos'; // Default para 'todos'


        const listaFuncionarios = await User.findAll({ where: { role: 'funcionario', EmpresaId: empresaId }, order: [['nome', 'ASC']] });

        let funcionariosParaProcessar = listaFuncionarios;
        if (funcIdSelecionado !== 'todos') {
            funcionariosParaProcessar = listaFuncionarios.filter(f => f.id == funcIdSelecionado);
        }

        const idsDosFuncionarios = funcionariosParaProcessar.map(u => u.id);

        let registrosNoPeriodo = [];
        let todasFerias = [];

        if (idsDosFuncionarios.length > 0) {
            // Constrói as datas de forma segura para query
            const dtInicio = new Date(`${inicio}T00:00:00-03:00`);
            const dtFim = new Date(`${fim}T23:59:59-03:00`);

            if (isNaN(dtInicio) || isNaN(dtFim)) {
                throw new Error("Datas inválidas para filtro.");
            }


            [registrosNoPeriodo, todasFerias] = await Promise.all([
                RegistroPonto.findAll({ where: { UserId: idsDosFuncionarios, timestamp: { [Op.between]: [dtInicio, dtFim] } } }),
                Ferias.findAll({ where: { UserId: idsDosFuncionarios } }) // Busca todas as férias para checar
            ]);
        }


        const faltas = [];
        let dataAtualLoop = new Date(`${inicio}T00:00:00-03:00`); // Usa fuso local
        const dataFinalObj = new Date(`${fim}T00:00:00-03:00`); // Usa fuso local


        while (dataAtualLoop <= dataFinalObj) {
            const diaDaSemana = dataAtualLoop.getDay(); // 0 = Domingo, 6 = Sábado

            // Pula fins de semana
            if (diaDaSemana !== 0 && diaDaSemana !== 6) {
                const dataFormatada = dataAtualLoop.toISOString().split('T')[0]; // YYYY-MM-DD

                for (const funcionario of funcionariosParaProcessar) {
                    // Verifica férias
                    const estaDeFerias = todasFerias.some(f => {
                        const inicioF = new Date(f.dataInicio + 'T00:00:00-03:00');
                        const fimF = new Date(f.dataFim + 'T23:59:59-03:00');
                        return dataAtualLoop >= inicioF && dataAtualLoop <= fimF;
                    });

                    if (estaDeFerias) continue; // Pula se estava de férias

                    // Verifica se tem algum registro no dia
                    const temRegistro = registrosNoPeriodo.some(r =>
                        r.UserId === funcionario.id &&
                        new Date(r.timestamp).toISOString().split('T')[0] === dataFormatada
                    );

                    if (!temRegistro) {
                        faltas.push({ nome: funcionario.nome, data: dataFormatada });
                    }
                }
            }
            // Avança para o próximo dia
            dataAtualLoop.setDate(dataAtualLoop.getDate() + 1);
        }

        res.render('relatorios', {
            faltas: faltas,
            dataInicio: inicio,
            dataFim: fim,
            listaFuncionarios: listaFuncionarios,
            funcionarioIdSelecionado: funcIdSelecionado
        });
    } catch (error) {
        console.error("Erro ao gerar relatório de faltas:", error);
        // Renderiza a página com erro
        res.render('relatorios', {
            faltas: [],
            dataInicio: req.query.dataInicio || new Date().toISOString().split('T')[0],
            dataFim: req.query.dataFim || new Date().toISOString().split('T')[0],
            listaFuncionarios: await User.findAll({ where: { role: 'funcionario', EmpresaId: req.session.empresaId }, order: [['nome', 'ASC']] }).catch(() => []), // Tenta buscar lista mesmo com erro
            funcionarioIdSelecionado: req.query.funcionarioId || 'todos',
            error: "Erro ao gerar relatório: " + error.message
        });
    }
});

// FOLHA DE PONTO SEMANAL (TELA)
app.get('/rh/relatorios/folha-ponto', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    // ... (código existente com ajustes similares de data padrão e tratamento de erro)
    try {
        const { empresaId } = req.session;
        const { dataInicio, dataFim, funcionarioId } = req.query;

        const hoje = new Date();
        const inicioMes = new Date(hoje.getFullYear(), hoje.getMonth(), 1).toISOString().split('T')[0];
        const hojeStr = hoje.toISOString().split('T')[0];

        const dataInicioSelecionada = dataInicio || inicioMes;
        const dataFimSelecionada = dataFim || hojeStr;
        const funcionarioIdSelecionado = funcionarioId; // Pode ser undefined inicialmente


        const listaFuncionarios = await User.findAll({ where: { role: 'funcionario', EmpresaId: empresaId }, order: [['nome', 'ASC']] });

        // Se nenhum funcionário ou data selecionada, apenas renderiza o formulário
        if (!funcionarioIdSelecionado) {
            return res.render('folha_ponto_semanal', {
                relatorioAgrupado: null,
                listaFuncionarios,
                dataInicioSelecionada,
                dataFimSelecionada,
                funcionarioIdSelecionado: null, // Indica que nada foi selecionado
                error: funcionarioId === '' ? 'Selecione um funcionário ou "Todos".' : null // Mensagem se tentou submeter sem selecionar
            });
        }


        const dataInicioObj = new Date(`${dataInicioSelecionada}T00:00:00-03:00`);
        const dataFimObj = new Date(`${dataFimSelecionada}T23:59:59-03:00`);

        if (isNaN(dataInicioObj) || isNaN(dataFimObj)) {
            return res.render('folha_ponto_semanal', {
                relatorioAgrupado: null, listaFuncionarios, dataInicioSelecionada, dataFimSelecionada, funcionarioIdSelecionado,
                error: "Datas inválidas fornecidas."
            });
        }


        let funcionariosParaProcessar = [];
        if (funcionarioIdSelecionado === 'todos') {
            funcionariosParaProcessar = listaFuncionarios;
        } else {
            const func = listaFuncionarios.find(f => f.id == funcionarioIdSelecionado);
            if (func) funcionariosParaProcessar.push(func);
        }

        if (funcionariosParaProcessar.length === 0 && funcionarioIdSelecionado !== 'todos') {
            return res.render('folha_ponto_semanal', {
                relatorioAgrupado: null, listaFuncionarios, dataInicioSelecionada, dataFimSelecionada, funcionarioIdSelecionado,
                error: "Funcionário selecionado não encontrado."
            });
        }
        if (funcionariosParaProcessar.length === 0 && funcionarioIdSelecionado === 'todos') {
            return res.render('folha_ponto_semanal', {
                relatorioAgrupado: null, listaFuncionarios, dataInicioSelecionada, dataFimSelecionada, funcionarioIdSelecionado,
                error: "Nenhum funcionário cadastrado nesta empresa."
            });
        }


        const idsDosFuncionarios = funcionariosParaProcessar.map(f => f.id);
        const [registros, ferias, configAlmoco] = await Promise.all([
            RegistroPonto.findAll({ where: { UserId: idsDosFuncionarios, timestamp: { [Op.between]: [dataInicioObj, dataFimObj] } }, order: [['timestamp', 'ASC']] }), // Ordena aqui
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

            const registrosDoFunc = registros.filter(r => r.UserId === funcionario.id); // Já ordenado
            const feriasDoFunc = ferias.filter(f => f.UserId === funcionario.id);

            let semanaAtual = {};
            let dataAtualLoop = new Date(dataInicioObj);

            while (dataAtualLoop <= dataFimObj) {
                const diaDaSemana = dataAtualLoop.getDay();
                const diaString = dataAtualLoop.toISOString().split('T')[0];

                if (diaDaSemana >= 1 && diaDaSemana <= 5) { // Segunda a Sexta
                    const registrosDoDia = registrosDoFunc.filter(r => new Date(r.timestamp).toISOString().split('T')[0] === diaString);
                    const diaInfo = {
                        data: new Date(dataAtualLoop), // Armazena como objeto Date
                        registros: registrosDoDia,
                        horasTrabalhadas: '00h 00m', saldoHoras: '', observacao: ''
                    };

                    const estaDeFerias = feriasDoFunc.some(f => {
                        const inicioF = new Date(f.dataInicio + 'T00:00:00-03:00');
                        const fimF = new Date(f.dataFim + 'T23:59:59-03:00');
                        const diaAtualNormalizado = new Date(diaString + 'T00:00:00-03:00');
                        return diaAtualNormalizado >= inicioF && diaAtualNormalizado <= fimF;
                    });

                    if (estaDeFerias) {
                        diaInfo.observacao = 'Férias'; diaInfo.horasTrabalhadas = '-'; diaInfo.saldoHoras = '-';
                    } else if (registrosDoDia.length === 0) {
                        diaInfo.observacao = 'Falta'; diaInfo.horasTrabalhadas = 'Falta';
                        try {
                            const expediente = getHorarioExpediente(funcionario, dataAtualLoop);
                            const [hE, mE] = expediente.entrada.split(':').map(Number);
                            const [hS, mS] = expediente.saida.split(':').map(Number);
                            const jornadaMin = ((hS - hE) * 60) + (mS - mE) - duracaoAlmoco;
                            const hSaldo = Math.floor(jornadaMin / 60).toString().padStart(2, '0');
                            const mSaldo = (jornadaMin % 60).toString().padStart(2, '0');
                            diaInfo.saldoHoras = `-${hSaldo}h ${mSaldo}m`;
                        } catch { diaInfo.saldoHoras = '-'; }
                    } else {
                        diaInfo.horasTrabalhadas = calcularHorasTrabalhadas(registrosDoDia);
                        if (!diaInfo.horasTrabalhadas.includes('Jornada em aberto') && !diaInfo.horasTrabalhadas.includes('(parcial)')) {
                            try {
                                const expediente = getHorarioExpediente(funcionario, dataAtualLoop);
                                const [hE, mE] = expediente.entrada.split(':').map(Number);
                                const [hS, mS] = expediente.saida.split(':').map(Number);
                                const jornadaMin = ((hS - hE) * 60) + (mS - mE) - duracaoAlmoco;
                                const match = diaInfo.horasTrabalhadas.match(/(\d{2})h (\d{2})m/);
                                if (match) {
                                    const hT = parseInt(match[1], 10); const mT = parseInt(match[2], 10);
                                    const trabalhadoMin = (hT * 60) + mT;
                                    const saldoMin = trabalhadoMin - jornadaMin;
                                    const sinal = saldoMin >= 0 ? '+' : '-';
                                    const hSaldo = Math.floor(Math.abs(saldoMin) / 60).toString().padStart(2, '0');
                                    const mSaldo = (Math.abs(saldoMin) % 60).toString().padStart(2, '0');
                                    diaInfo.saldoHoras = `${sinal}${hSaldo}h ${mSaldo}m`;
                                } else { diaInfo.saldoHoras = 'Erro Calc'; }
                            } catch (calcError) {
                                console.error("Erro calc saldo folha ponto:", calcError);
                                diaInfo.saldoHoras = 'Erro Calc';
                            }
                        } else {
                            diaInfo.saldoHoras = '-';
                        }
                    }

                    const dias = ['domingo', 'segunda', 'terca', 'quarta', 'quinta', 'sexta', 'sabado'];
                    semanaAtual[dias[diaDaSemana]] = diaInfo;
                }

                // Fecha a semana na Sexta ou no último dia do período
                if (diaDaSemana === 5 || dataAtualLoop.getTime() >= dataFimObj.getTime()) {
                    if (Object.keys(semanaAtual).length > 0) {
                        const primeiraDataDaSemana = Object.values(semanaAtual)[0]?.data;
                        if (primeiraDataDaSemana) semanaAtual.dataInicioSemana = primeiraDataDaSemana;
                        dadosFuncionario.semanas.push(semanaAtual);
                    }
                    semanaAtual = {};
                }

                dataAtualLoop.setDate(dataAtualLoop.getDate() + 1);
            }

            // Ordena as semanas
            dadosFuncionario.semanas.sort((a, b) => (a.dataInicioSemana || 0) - (b.dataInicioSemana || 0));

            relatorioAgrupado.push(dadosFuncionario);
        }

        res.render('folha_ponto_semanal', {
            relatorioAgrupado,
            listaFuncionarios,
            dataInicioSelecionada,
            dataFimSelecionada,
            funcionarioIdSelecionado
        });

    } catch (error) {
        console.error("Erro ao gerar folha de ponto semanal:", error);
        res.render('folha_ponto_semanal', {
            relatorioAgrupado: null,
            listaFuncionarios: await User.findAll({ where: { role: 'funcionario', EmpresaId: req.session.empresaId }, order: [['nome', 'ASC']] }).catch(() => []),
            dataInicioSelecionada: req.query.dataInicio || new Date().toISOString().split('T')[0].substring(0, 8) + '01',
            dataFimSelecionada: req.query.dataFim || new Date().toISOString().split('T')[0],
            funcionarioIdSelecionado: req.query.funcionarioId,
            error: "Ocorreu um erro ao gerar o relatório: " + error.message
        });
    }
});

// DOWNLOAD FOLHA DE PONTO CSV
app.get('/rh/relatorios/folha-ponto/download', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const { empresaId } = req.session;
        const { dataInicio, dataFim, funcionarioId } = req.query;

        if (!dataInicio || !dataFim || !funcionarioId) {
            return res.status(400).send("Parâmetros de filtro ausentes (dataInicio, dataFim, funcionarioId).");
        }

        const dataInicioObj = new Date(`${dataInicio}T00:00:00-03:00`);
        const dataFimObj = new Date(`${dataFim}T23:59:59-03:00`);

        if (isNaN(dataInicioObj) || isNaN(dataFimObj)) {
            return res.status(400).send("Datas fornecidas são inválidas.");
        }


        // --- LÓGICA DE BUSCA E PROCESSAMENTO (Idêntica à rota GET /rh/relatorios/folha-ponto) ---
        let funcionariosParaProcessar = [];
        const listaFuncionarios = await User.findAll({ where: { role: 'funcionario', EmpresaId: empresaId }, order: [['nome', 'ASC']] });
        if (funcionarioId === 'todos') {
            funcionariosParaProcessar = listaFuncionarios;
        } else {
            const func = listaFuncionarios.find(f => f.id == funcionarioId);
            if (func) funcionariosParaProcessar.push(func);
        }

        if (funcionariosParaProcessar.length === 0) {
            let msg = funcionarioId === 'todos' ? "Nenhum funcionário na empresa." : "Funcionário não encontrado.";
            return res.status(404).send(msg);
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

                // --- Lógica para criar diaInfo ---
                const diaInfo = {
                    funcionarioNome: funcionario.nome,
                    data: new Date(dataAtualLoop),
                    registros: registrosDoDia,
                    horasTrabalhadas: '00h 00m',
                    saldoHoras: '',
                    observacao: ''
                };

                if (diaDaSemana === 0 || diaDaSemana === 6) { // Fim de semana
                    diaInfo.observacao = 'Fim de semana';
                    diaInfo.horasTrabalhadas = '-'; diaInfo.saldoHoras = '-';
                } else { // Dia útil
                    const feriasDoFunc = feriasPorUsuario[funcionario.id] || [];
                    const estaDeFerias = feriasDoFunc.some(f => {
                        const inicioF = new Date(f.dataInicio + 'T00:00:00-03:00');
                        const fimF = new Date(f.dataFim + 'T23:59:59-03:00');
                        const diaAtualNormalizado = new Date(diaString + 'T00:00:00-03:00');
                        return diaAtualNormalizado >= inicioF && diaAtualNormalizado <= fimF;
                    });
                    if (estaDeFerias) {
                        diaInfo.observacao = 'Férias'; diaInfo.horasTrabalhadas = '-'; diaInfo.saldoHoras = '-';
                    }
                    // --- BLOCO CORRIGIDO ---
                    else if (diaInfo.registros.length === 0) {
                        diaInfo.observacao = 'Falta'; diaInfo.horasTrabalhadas = 'Falta';
                        try {
                            const exp = getHorarioExpediente(funcionario, dataAtualLoop);
                            const [hE, mE] = exp.entrada.split(':').map(Number);
                            const [hS_expediente, mS_expediente] = exp.saida.split(':').map(Number); // Renomeado
                            const jornadaMin = ((hS_expediente - hE) * 60) + (mS_expediente - mE) - duracaoAlmoco;
                            const hSaldo = Math.floor(jornadaMin / 60).toString().padStart(2, '0'); // Renomeado
                            const mSaldo = (jornadaMin % 60).toString().padStart(2, '0'); // Renomeado
                            diaInfo.saldoHoras = `-${hSaldo}h ${mSaldo}m`; // Usa renomeados
                        } catch (calcError) {
                            console.error("Erro ao calcular saldo de falta (Download):", calcError);
                            diaInfo.saldoHoras = '-';
                        }
                    }
                    // --- FIM BLOCO CORRIGIDO ---
                    else {
                        diaInfo.horasTrabalhadas = calcularHorasTrabalhadas(diaInfo.registros);
                        if (!diaInfo.horasTrabalhadas.includes('Jornada em aberto') && !diaInfo.horasTrabalhadas.includes('(parcial)')) {
                            try {
                                const expediente = getHorarioExpediente(funcionario, dataAtualLoop);
                                const [hE, mE] = expediente.entrada.split(':').map(Number);
                                const [hS, mS] = expediente.saida.split(':').map(Number);
                                const jornadaMin = ((hS - hE) * 60) + (mS - mE) - duracaoAlmoco;
                                const match = diaInfo.horasTrabalhadas.match(/(\d{2})h (\d{2})m/);
                                if (match) {
                                    const hT = parseInt(match[1], 10); const mT = parseInt(match[2], 10);
                                    const trabalhadoMin = (hT * 60) + mT;
                                    const saldoMin = trabalhadoMin - jornadaMin;
                                    const sinal = saldoMin >= 0 ? '+' : '-';
                                    const hSaldo = Math.floor(Math.abs(saldoMin) / 60).toString().padStart(2, '0');
                                    const mSaldo = (Math.abs(saldoMin) % 60).toString().padStart(2, '0');
                                    diaInfo.saldoHoras = `${sinal}${hSaldo}h ${mSaldo}m`;
                                } else { diaInfo.saldoHoras = 'Erro Calc'; }
                            } catch (calcError) {
                                console.error("Erro calc saldo folha ponto (Download):", calcError);
                                diaInfo.saldoHoras = 'Erro Calc';
                            }
                        } else {
                            diaInfo.saldoHoras = '-';
                        }
                    }
                }
                // --- Fim lógica diaInfo ---
                relatorio.push(diaInfo);
            }
            dataAtualLoop.setDate(dataAtualLoop.getDate() + 1);
        }
        relatorio.sort((a, b) => a.data - b.data || a.funcionarioNome.localeCompare(b.funcionarioNome));

        // =================================================================
        // LÓGICA PARA GERAR O ARQUIVO CSV (mantida)
        // =================================================================
        const isForAll = funcionarioId === 'todos';
        let csvHeader = (isForAll ? 'Funcionario,' : '') + 'Data,Dia da Semana,Registros,Total Trabalhado,Saldo do Dia,Observacao\n';

        const csvRows = relatorio.map(dia => {
            const funcionarioCsv = isForAll ? `"${dia.funcionarioNome.replace(/"/g, '""')}",` : '';
            const dataCsv = dia.data.toLocaleDateString('pt-BR');
            const diaSemanaCsv = dia.data.toLocaleDateString('pt-BR', { weekday: 'long' });
            const registrosStr = dia.registros.map(r => `${r.tipo}: ${new Date(r.timestamp).toLocaleTimeString('pt-BR')}`).join(' | ');

            // Escapa aspas na observação
            const observacaoCsv = dia.observacao ? dia.observacao.replace(/"/g, '""') : '';

            return `${funcionarioCsv}${dataCsv},${diaSemanaCsv},"${registrosStr}","${dia.horasTrabalhadas}","${dia.saldoHoras}","${observacaoCsv}"`;
        }).join('\n');

        const csvContent = "\uFEFF" + csvHeader + csvRows; // BOM para Excel

        const filename = `folha_ponto_${dataInicio}_a_${dataFim}${isForAll ? '_todos' : '_' + funcionarioId}.csv`;
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.status(200).send(Buffer.from(csvContent, 'utf-8'));

    } catch (error) {
        console.error("Erro ao gerar download da folha de ponto:", error);
        res.status(500).send('Ocorreu um erro ao gerar o arquivo CSV.');
    }
});

// DOWNLOAD RELATÓRIO DE FALTAS CSV
app.get('/rh/relatorios/download', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    // ... (código existente com validação de datas e funcionário)
    try {
        const { empresaId } = req.session;
        const { dataInicio, dataFim, funcionarioId } = req.query;

        if (!dataInicio || !dataFim) {
            return res.status(400).send("Datas de início e fim são obrigatórias.");
        }
        const funcIdSelecionado = funcionarioId || 'todos';

        const dtInicio = new Date(`${dataInicio}T00:00:00-03:00`);
        const dtFim = new Date(`${dataFim}T23:59:59-03:00`);
        if (isNaN(dtInicio) || isNaN(dtFim)) {
            return res.status(400).send("Datas fornecidas são inválidas.");
        }

        // --- LÓGICA DE BUSCA E PROCESSAMENTO (Idêntica à rota GET /rh/relatorios) ---
        const listaFuncionarios = await User.findAll({ where: { role: 'funcionario', EmpresaId: empresaId }, order: [['nome', 'ASC']] });
        let funcionariosParaProcessar = listaFuncionarios;
        if (funcIdSelecionado !== 'todos') {
            funcionariosParaProcessar = listaFuncionarios.filter(f => f.id == funcIdSelecionado);
        }

        if (funcionariosParaProcessar.length === 0) {
            return res.status(404).send(funcIdSelecionado === 'todos' ? 'Nenhum funcionário.' : 'Funcionário não encontrado.');
        }

        const idsDosFuncionarios = funcionariosParaProcessar.map(u => u.id);
        let registrosNoPeriodo = [];
        let todasFerias = [];
        if (idsDosFuncionarios.length > 0) {
            [registrosNoPeriodo, todasFerias] = await Promise.all([
                RegistroPonto.findAll({ where: { UserId: idsDosFuncionarios, timestamp: { [Op.between]: [dtInicio, dtFim] } } }),
                Ferias.findAll({ where: { UserId: idsDosFuncionarios } })
            ]);
        }

        const faltas = [];
        let dataAtualLoop = new Date(dtInicio);
        const dataFinalObj = new Date(dtFim);

        while (dataAtualLoop <= dataFinalObj) {
            const diaDaSemana = dataAtualLoop.getDay();
            if (diaDaSemana !== 0 && diaDaSemana !== 6) { // Pula fds
                const dataFormatada = dataAtualLoop.toISOString().split('T')[0];
                for (const funcionario of funcionariosParaProcessar) {
                    const estaDeFerias = todasFerias.some(f => {
                        const inicioF = new Date(f.dataInicio + 'T00:00:00-03:00');
                        const fimF = new Date(f.dataFim + 'T23:59:59-03:00');
                        return dataAtualLoop >= inicioF && dataAtualLoop <= fimF;
                    });
                    if (estaDeFerias) continue;

                    const temRegistro = registrosNoPeriodo.some(r =>
                        r.UserId === funcionario.id &&
                        new Date(r.timestamp).toISOString().split('T')[0] === dataFormatada
                    );
                    if (!temRegistro) {
                        faltas.push({
                            nome: funcionario.nome.replace(/,/g, ''), // Remove vírgulas do nome
                            data: dataAtualLoop.toLocaleDateString('pt-BR') // Formato DD/MM/YYYY
                        });
                    }
                }
            }
            dataAtualLoop.setDate(dataAtualLoop.getDate() + 1);
        }
        // --- Fim Lógica ---

        const csvHeader = 'Funcionario,Data da Falta\n';
        const csvRows = faltas.map(f => `"${f.nome}",${f.data}`).join('\n'); // Adiciona aspas ao nome
        const csvContent = "\uFEFF" + csvHeader + csvRows; // BOM

        const filename = `relatorio_faltas_${dataInicio}_a_${dataFim}${funcIdSelecionado === 'todos' ? '' : '_' + funcIdSelecionado}.csv`;
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.status(200).send(Buffer.from(csvContent, 'utf-8'));
    } catch (error) {
        console.error("Erro ao gerar download de relatório de faltas:", error);
        res.status(500).send('Ocorreu um erro ao gerar o arquivo CSV de faltas.');
    }
});

// GERAR ESPELHO DE PONTO PDF
// MODIFICADO para usar puppeteer condicional e logo Base64
app.get('/rh/relatorios/folha-ponto/pdf', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        // --- Validação de Parâmetros ---
        const { empresaId } = req.session;
        const { dataInicio, dataFim, funcionarioId } = req.query;

        if (!dataInicio || !dataFim || !funcionarioId) {
            return res.status(400).send("Parâmetros de filtro ausentes para gerar o PDF (dataInicio, dataFim, funcionarioId).");
        }

        const dataInicioObj = new Date(`${dataInicio}T00:00:00-03:00`);
        const dataFimObj = new Date(`${dataFim}T23:59:59-03:00`);

        if (isNaN(dataInicioObj) || isNaN(dataFimObj)) {
            return res.status(400).send("Datas fornecidas são inválidas.");
        }

        // --- LÓGICA DE BUSCA E PROCESSAMENTO DE DADOS ---
        const listaFuncionarios = await User.findAll({ where: { role: 'funcionario', EmpresaId: empresaId }, order: [['nome', 'ASC']] });
        let funcionariosParaProcessar = [];
        if (funcionarioId === 'todos') {
            funcionariosParaProcessar = listaFuncionarios;
        } else {
            const func = listaFuncionarios.find(f => f.id == funcionarioId);
            if (func) funcionariosParaProcessar.push(func);
        }

        if (funcionariosParaProcessar.length === 0) {
            return res.status(404).send(funcionarioId === 'todos' ? 'Nenhum funcionário.' : 'Funcionário não encontrado.');
        }

        const empresa = await Empresa.findByPk(empresaId, { attributes: ['nome', 'cnpj', 'logoPath'] }); // Busca logoPath

        const idsDosFuncionarios = funcionariosParaProcessar.map(f => f.id);
        const [registros, ferias, configAlmoco] = await Promise.all([
            RegistroPonto.findAll({ where: { UserId: idsDosFuncionarios, timestamp: { [Op.between]: [dataInicioObj, dataFimObj] } }, order: [['timestamp', 'ASC']] }),
            Ferias.findAll({ where: { UserId: idsDosFuncionarios } }),
            Configuracao.findOne({ where: { chave: 'duracao_almoco_minutos', EmpresaId: empresaId } })
        ]);
        const duracaoAlmoco = configAlmoco ? parseInt(configAlmoco.valor, 10) : 60;
        const relatorioAgrupado = [];

        for (const funcionario of funcionariosParaProcessar) {
            const dadosFuncionario = { id: funcionario.id, nome: funcionario.nome, semanas: [] };
            const registrosDoFunc = registros.filter(r => r.UserId === funcionario.id);
            const feriasDoFunc = ferias.filter(f => f.UserId === funcionario.id);
            let semanaAtual = {};
            let dataAtualLoop = new Date(dataInicioObj);
            while (dataAtualLoop <= dataFimObj) {
                const diaDaSemana = dataAtualLoop.getDay();
                const diaString = dataAtualLoop.toISOString().split('T')[0];
                if (diaDaSemana >= 1 && diaDaSemana <= 5) {
                    const registrosDoDia = registrosDoFunc.filter(r => new Date(r.timestamp).toISOString().split('T')[0] === diaString);
                    const diaInfo = { data: new Date(dataAtualLoop), registros: registrosDoDia, horasTrabalhadas: '00h 00m', saldoHoras: '', observacao: '' };
                    const estaDeFerias = feriasDoFunc.some(f => { const inicioF = new Date(f.dataInicio + 'T00:00:00-03:00'); const fimF = new Date(f.dataFim + 'T23:59:59-03:00'); const diaNorm = new Date(diaString + 'T00:00:00-03:00'); return diaNorm >= inicioF && diaNorm <= fimF; });
                    if (estaDeFerias) { diaInfo.observacao = 'Férias'; diaInfo.horasTrabalhadas = '-'; diaInfo.saldoHoras = '-'; }
                    // --- BLOCO CORRIGIDO ---
                    else if (registrosDoDia.length === 0) {
                        diaInfo.observacao = 'Falta'; diaInfo.horasTrabalhadas = 'Falta';
                        try {
                            const exp = getHorarioExpediente(funcionario, dataAtualLoop);
                            const [hE, mE] = exp.entrada.split(':').map(Number);
                            const [hS_expediente, mS_expediente] = exp.saida.split(':').map(Number); // Renomeado
                            const jornadaMin = ((hS_expediente - hE) * 60) + (mS_expediente - mE) - duracaoAlmoco;
                            const hSaldo = Math.floor(jornadaMin / 60).toString().padStart(2, '0'); // Renomeado
                            const mSaldo = (jornadaMin % 60).toString().padStart(2, '0'); // Renomeado
                            diaInfo.saldoHoras = `-${hSaldo}h ${mSaldo}m`; // Usa renomeados
                        } catch (calcError) {
                            console.error("Erro ao calcular saldo de falta (PDF):", calcError);
                            diaInfo.saldoHoras = '-';
                        }
                    }
                    // --- FIM BLOCO CORRIGIDO ---
                    else { diaInfo.horasTrabalhadas = calcularHorasTrabalhadas(registrosDoDia); if (!diaInfo.horasTrabalhadas.includes('Jornada em aberto') && !diaInfo.horasTrabalhadas.includes('(parcial)')) { try { const exp = getHorarioExpediente(funcionario, dataAtualLoop); const [hE, mE] = exp.entrada.split(':').map(Number); const [hS, mS] = exp.saida.split(':').map(Number); const jMin = ((hS - hE) * 60) + (mS - mE) - duracaoAlmoco; const match = diaInfo.horasTrabalhadas.match(/(\d{2})h (\d{2})m/); if (match) { const hT = parseInt(match[1], 10); const mT = parseInt(match[2], 10); const tMin = (hT * 60) + mT; const sMin = tMin - jMin; const sig = sMin >= 0 ? '+' : '-'; const hSaldo = Math.floor(Math.abs(sMin) / 60).toString().padStart(2, '0'); const mSaldo = (Math.abs(sMin) % 60).toString().padStart(2, '0'); diaInfo.saldoHoras = `${sig}${hSaldo}h ${mSaldo}m`; } else { diaInfo.saldoHoras = 'Erro Calc'; } } catch (calcError) { console.error("Erro calc saldo folha ponto (PDF):", calcError); diaInfo.saldoHoras = 'Erro Calc'; } } else { diaInfo.saldoHoras = '-'; } }
                    const dias = ['domingo', 'segunda', 'terca', 'quarta', 'quinta', 'sexta', 'sabado'];
                    semanaAtual[dias[diaDaSemana]] = diaInfo;
                }
                if (diaDaSemana === 5 || dataAtualLoop.getTime() >= dataFimObj.getTime()) { if (Object.keys(semanaAtual).length > 0) { const pData = Object.values(semanaAtual)[0]?.data; if (pData) semanaAtual.dataInicioSemana = pData; dadosFuncionario.semanas.push(semanaAtual); } semanaAtual = {}; }
                dataAtualLoop.setDate(dataAtualLoop.getDate() + 1);
            }
            dadosFuncionario.semanas.sort((a, b) => (a.dataInicioSemana || 0) - (b.dataInicioSemana || 0));
            relatorioAgrupado.push(dadosFuncionario);
        }
        // --- Fim Lógica de Busca ---


        // =================================================================
        // LÓGICA DE GERAÇÃO DE PDF ATUALIZADA (com logo Base64)
        // =================================================================
        const filePath = path.join(__dirname, 'views', 'espelho_ponto_pdf.ejs');

        let logoBase64 = null;
        if (empresa && empresa.logoPath) {
            const logoFullPath = path.join(__dirname, 'public', empresa.logoPath);
            if (fs.existsSync(logoFullPath)) {
                try {
                    const logoBuffer = fs.readFileSync(logoFullPath);
                    let mimeType = 'image/jpeg'; // Default
                    const ext = path.extname(empresa.logoPath).toLowerCase();
                    if (ext === '.png') mimeType = 'image/png';
                    else if (ext === '.gif') mimeType = 'image/gif';
                    else if (ext === '.webp') mimeType = 'image/webp';
                    logoBase64 = `data:${mimeType};base64,${logoBuffer.toString('base64')}`;
                } catch (readErr) {
                    console.error("Erro ao ler/converter logo para PDF:", readErr);
                    // Continua sem logo se der erro
                }
            } else {
                console.warn("Arquivo de logo não encontrado para PDF:", logoFullPath);
            }
        }

        const html = await ejs.renderFile(filePath, {
            relatorioAgrupado,
            dataInicio: dataInicio, // Passa como string YYYY-MM-DD
            dataFim: dataFim,       // Passa como string YYYY-MM-DD
            empresa: {
                nome: empresa ? empresa.nome : 'Empresa',
                cnpj: empresa ? empresa.cnpj : null,
                logoBase64: logoBase64 // Passa string Base64 ou null
            }
        });

        // --- Lógica Puppeteer Condicional ---
        let browser;
        try {
            // Verifica se puppeteer está inicializado (importante devido ao async no topo)
            if (!puppeteer || typeof puppeteer.launch !== 'function') {
                console.error("Puppeteer não foi inicializado corretamente. Verifique o bloco async no topo.");
                throw new Error("Puppeteer não inicializado.");
            }
            console.log("Iniciando Puppeteer com args:", chromiumArgs);
            browser = await puppeteer.launch({
                ...chromiumArgs, // Usa args de produção ou {} localmente
                defaultViewport: null, // Usa viewport do format 'A4'
                // Adicione args extras se necessário, especialmente para Linux/Render
                args: [
                    ...(chromiumArgs.args || []), // Mantém args originais
                    '--no-sandbox',               // Comum em ambientes Linux/Docker/Serverless
                    '--disable-setuid-sandbox',   // Comum
                    '--disable-dev-shm-usage',    // Ajuda a evitar erros de memória compartilhada
                    '--disable-gpu'               // Pode ajudar em ambientes sem GPU
                ]
            });

            const page = await browser.newPage();
            // Define conteúdo com timeout maior
            await page.setContent(html, { waitUntil: 'networkidle0', timeout: 60000 }); // 60s timeout

            const pdfBuffer = await page.pdf({
                format: 'A4',
                printBackground: true,
                margin: { top: '25px', right: '25px', bottom: '25px', left: '25px' }
            });

            await browser.close(); // Fecha o navegador

            const filename = `espelho_ponto_${dataInicio}_a_${dataFim}${funcionarioId === 'todos' ? '' : '_' + funcionarioId}.pdf`;
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.send(pdfBuffer);

        } catch (launchError) {
            console.error("Erro CRÍTICO ao iniciar ou usar Puppeteer:", launchError);
            if (browser) {
                await browser.close().catch(closeErr => console.error("Erro ao fechar browser após falha:", closeErr));
            }
            // Tenta identificar o erro ENOENT
            if (launchError.message && (launchError.message.includes('ENOENT') || launchError.message.includes('Failed to launch'))) {
                res.status(500).send('Erro ao gerar o PDF: O navegador Chromium não foi encontrado ou falhou ao iniciar. Verifique a instalação do Puppeteer localmente ou as dependências/configurações no servidor.');
            } else {
                res.status(500).send('Ocorreu um erro inesperado ao gerar o PDF.');
            }
        }
        // --- Fim Lógica Puppeteer ---

    } catch (error) { // Catch geral da rota
        console.error("Erro GERAL ao gerar PDF do espelho de ponto:", error);
        res.status(500).send('Ocorreu um erro geral ao processar a solicitação do PDF.');
    }
});
// --- FIM MODIFICAÇÃO PDF ---


// ROTA PARA EXCLUIR REGISTRO DE PONTO ESPECÍFICO
app.post('/rh/registro/excluir/:id', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const registroId = req.params.id;
        const { empresaId } = req.session;

        if (!registroId || isNaN(parseInt(registroId))) {
            return res.status(400).send('ID de registro inválido.');
        }

        // Verifica se o registro pertence a um usuário da empresa do RH
        const registro = await RegistroPonto.findOne({
            where: { id: registroId },
            include: { model: User, where: { EmpresaId: empresaId }, attributes: [] } // Apenas para join, não precisa dos dados do User
        });

        if (!registro) {
            return res.status(404).send('Registro de ponto não encontrado ou não pertence à sua empresa.');
        }

        await RegistroPonto.destroy({ where: { id: registroId } });

        // Redireciona de volta para onde veio (ou dashboard como fallback)
        const backURL = req.header('Referer') || '/rh/dashboard';
        res.redirect(backURL + '?msg=registro_excluido');

    } catch (error) {
        console.error("Erro ao excluir registro de ponto:", error);
        res.status(500).send('Ocorreu um erro ao tentar excluir o registro.');
    }
});

// ROTA PARA MOSTRAR O FORMULÁRIO DE LANÇAMENTO MANUAL
app.get('/rh/registro-manual/:userId', checarAutenticacao, checarAutorizacaoRH, async (req, res) => {
    try {
        const userId = req.params.userId;
        if (!userId || isNaN(parseInt(userId))) {
            return res.status(400).send('ID de funcionário inválido.');
        }
        const funcionario = await User.findOne({
            where: { id: userId, EmpresaId: req.session.empresaId, role: 'funcionario' }
        });

        if (!funcionario) {
            return res.status(404).send('Funcionário não encontrado ou não pertence à sua empresa.');
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
        const { empresaId } = req.session;

        if (!userId || isNaN(parseInt(userId))) {
            return res.status(400).send('ID de funcionário inválido.');
        }
        if (!data) {
            // Recarrega o form com erro
            const funcionario = await User.findByPk(userId);
            return res.render('registro_manual', { funcionario, error: 'A data é obrigatória.' });
        }
        // Valida se o funcionário pertence à empresa
        const funcionario = await User.findOne({ where: { id: userId, EmpresaId: empresaId, role: 'funcionario' } });
        if (!funcionario) return res.status(404).send('Funcionário não pertence à sua empresa.');


        // Constrói os timestamps com fuso horário correto (-03:00)
        const criarTimestamp = (horario) => {
            if (!horario) return null;
            try {
                // Tenta criar a data. O formato "YYYY-MM-DDTHH:mm:ss.sssZ" ou com offset é mais robusto
                const dt = new Date(`${data}T${horario}:00-03:00`);
                if (isNaN(dt)) return null; // Retorna null se a data for inválida
                return dt;
            } catch {
                return null; // Retorna null se der erro na construção
            }
        };

        const timestamps = {
            Entrada: criarTimestamp(entrada),
            'Saida Almoço': criarTimestamp(saidaAlmoco),
            'Volta Almoço': criarTimestamp(voltaAlmoco),
            Saida: criarTimestamp(saida)
        };

        // Validação de ordem (básica)
        if (timestamps['Saida Almoço'] && timestamps.Entrada && timestamps['Saida Almoço'] < timestamps.Entrada) return res.render('registro_manual', { funcionario, error: 'Saída Almoço não pode ser antes da Entrada.', formData: req.body });
        if (timestamps['Volta Almoço'] && timestamps['Saida Almoço'] && timestamps['Volta Almoço'] < timestamps['Saida Almoço']) return res.render('registro_manual', { funcionario, error: 'Volta Almoço não pode ser antes da Saída Almoço.', formData: req.body });
        if (timestamps.Saida && timestamps['Volta Almoço'] && timestamps.Saida < timestamps['Volta Almoço']) return res.render('registro_manual', { funcionario, error: 'Saída não pode ser antes da Volta Almoço.', formData: req.body });
        if (timestamps.Saida && !timestamps['Volta Almoço'] && timestamps.Entrada && timestamps.Saida < timestamps.Entrada) return res.render('registro_manual', { funcionario, error: 'Saída não pode ser antes da Entrada.', formData: req.body });


        // Deleta registros existentes para este dia ANTES de inserir os novos
        const inicioDiaSelecionado = new Date(`${data}T00:00:00-03:00`);
        const fimDiaSelecionado = new Date(`${data}T23:59:59-03:00`);
        await RegistroPonto.destroy({
            where: {
                UserId: userId,
                timestamp: { [Op.between]: [inicioDiaSelecionado, fimDiaSelecionado] }
            }
        });


        // Cria os novos registros (apenas os que têm horário válido)
        const registrosParaCriar = [];
        for (const tipo in timestamps) {
            if (timestamps[tipo]) {
                registrosParaCriar.push({
                    UserId: userId,
                    tipo: tipo,
                    timestamp: timestamps[tipo]
                });
            }
        }

        // Ordena por timestamp antes de salvar (garante ordem no DB se houver microsegundos iguais)
        registrosParaCriar.sort((a, b) => a.timestamp - b.timestamp);

        // Insere todos de uma vez
        if (registrosParaCriar.length > 0) {
            await RegistroPonto.bulkCreate(registrosParaCriar);
        }

        res.redirect('/rh/dashboard?msg=registro_manual_ok');

    } catch (error) {
        console.error("Erro ao salvar registro manual:", error);
        const userId = req.params.userId;
        try {
            const funcionario = await User.findByPk(userId);
            res.render('registro_manual', { funcionario, error: 'Ocorreu um erro ao salvar os registros.', formData: req.body });
        } catch (findError) {
            res.status(500).send("Ocorreu um erro ao salvar os registros e ao recarregar o formulário.");
        }
    }
});

// Rota Raiz
app.get('/', (req, res) => {
    if (req.session.userId) {
        // Verifica o role para redirecionar corretamente
        if (req.session.userRole === 'rh') {
            res.redirect('/rh/dashboard');
        } else {
            res.redirect('/dashboard');
        }
    } else {
        res.redirect('/login');
    }
});


// =================================================================
// FUNÇÕES E INICIALIZAÇÃO DO SERVIDOR
// =================================================================
async function iniciarSistema() {
    try {
        const adminEmail = process.env.ADMIN_EMAIL || 'rh@empresa.com';
        const adminSenha = process.env.ADMIN_SENHA || 'senha123';

        // Tenta encontrar a empresa padrão ou criar
        const [empresa, criadaEmpresa] = await Empresa.findOrCreate({
            where: { nome: 'Empresa Matriz (Padrão)' },
            defaults: { nome: 'Empresa Matriz (Padrão)' } // Só adiciona nome na criação
        });

        if (criadaEmpresa) {
            console.log(`Empresa Padrão (ID: ${empresa.id}) criada.`);
            // Se criou a empresa, cria as configs padrão para ela
            await Configuracao.bulkCreate([
                { chave: 'allowed_ips', valor: '', EmpresaId: empresa.id }, // IP Vazio por padrão
                { chave: 'duracao_almoco_minutos', valor: '60', EmpresaId: empresa.id }
            ]);
            console.log(`Configurações padrão criadas para Empresa ID: ${empresa.id}`);
        }

        // Tenta encontrar o usuário admin ou criar
        const [userAdmin, criadoUser] = await User.findOrCreate({
            where: { email: adminEmail },
            defaults: {
                nome: 'Admin RH',
                senha: await bcrypt.hash(adminSenha, 10),
                role: 'rh',
                EmpresaId: empresa.id // Associa à empresa padrão
            }
        });

        if (criadoUser) {
            console.log('Usuário RH Padrão criado.');
        } else {
            // Garante que o usuário existente é RH e pertence à empresa padrão
            if (userAdmin.role !== 'rh' || userAdmin.EmpresaId !== empresa.id) {
                console.warn(`Usuário ${adminEmail} existe mas não é RH ou não pertence à Empresa Padrão. Atualizando...`);
                await userAdmin.update({ role: 'rh', EmpresaId: empresa.id });
            }
        }
    } catch (error) {
        console.error("Erro crítico durante a inicialização do sistema (iniciarSistema):", error);
        // Considerar encerrar o processo se a inicialização falhar criticamente
        // process.exit(1);
    }
}


async function criarTabelaDeSessaoSeNaoExistir() {
    // Só executa em produção onde usamos Postgres para sessão
    if (process.env.NODE_ENV !== 'production') {
        return;
    }
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
            WHERE conname = 'session_pkey' AND conrelid = (SELECT oid FROM pg_class WHERE relname = 'session')
        ) THEN
            ALTER TABLE "session" ADD CONSTRAINT "session_pkey" PRIMARY KEY ("sid");
        END IF;
    END;
    $$;
    CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
    `;
    try {
        await sequelize.query(query);
        console.log('Tabela de sessão Postgres verificada/criada com sucesso.');
    } catch (error) {
        console.error('Erro ao verificar/criar tabela de sessão Postgres:', error);
        // Considerar logar erro e continuar, ou parar se for crítico
    }
}

// --- BLOCO DE INICIALIZAÇÃO ATUALIZADO ---
// Usa async/await para garantir a ordem
(async () => {
    try {
        await sequelize.sync({ alter: process.env.NODE_ENV !== 'production' }); // Use alter: true com cuidado em dev, NUNCA em prod
        console.log('Modelos sincronizados com o banco de dados.');
        await iniciarSistema(); // Cria empresa/admin padrão se necessário
        await criarTabelaDeSessaoSeNaoExistir(); // Cria tabela de sessão no Postgres (produção)
        app.listen(port, () => {
            console.log(`Servidor rodando em http://localhost:${port} no modo ${process.env.NODE_ENV || 'development'}`);
        });
    } catch (err) {
        console.error('Erro GERAL ao conectar ou sincronizar com o banco de dados:', err);
        process.exit(1); // Encerra se não conseguir conectar ao DB
    }
})();
