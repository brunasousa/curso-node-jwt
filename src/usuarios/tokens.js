const crypto = require('crypto');
const moment = require('moment');
const jwt = require('jsonwebtoken');

const allowListRefreshToken = require('../../redis/allowlist-refresh-token');
const blocklistAccessToken = require('../../redis/blocklist-access-token');
const { InvalidArgumentError } = require('../erros');

function criaTokenJWT(id, [tempoQuantidade, tempoUnidade]) {
    const payload = {
      id: id,
    };
  
    const token = jwt.sign(payload, process.env.CHAVE_JWT, { expiresIn: tempoQuantidade+tempoUnidade });
    return token;
}
  
async function criaTokenOpaco(id, [tempoQuantidade, tempoUnidade], allowList) {
    const tokenOpaco = crypto.randomBytes(24).toString('hex');
    const dataExpiracao = moment().add(tempoQuantidade, tempoUnidade).unix();
    await allowList.adiciona(tokenOpaco, id, dataExpiracao);
    return tokenOpaco;
}

async function verificaTokenJWT(token, nomeToken, blocklist) {
    await verificaTokenNaBlocklist(token, nomeToken, blocklist);
    const { id } = jwt.verify(token, process.env.CHAVE_JWT);
    return id;
}

async function verificaTokenNaBlocklist(token, nomeToken, blocklist) {
    if (!blocklist) {
        return;
    }

    const tokenNaBlocklist = await blocklist.contemToken(token);
    if (tokenNaBlocklist) {
      throw new jwt.JsonWebTokenError(`${nomeToken} inválido por logout!`);
    }
}

async function verificaTokenOpaco(token, nomeToken, allowList) {
    verificaTokenEnviado(token, nomeToken);
    const id = await allowList.buscaValor(token);
    verificaTokenValido(id, nomeToken);
  
    return id;
}

async function invalidaTokenJWT(token, blocklist) {
    return blocklist.adiciona(token);
}


async function invalidaTokenOpaco(token, allowlist) {
    await allowlist.deleta(token);
  }

module.exports = {
    access: {
        nome: 'access token',
        lista: blocklistAccessToken,
        expiracao: [15, 'm'],
        cria(id) {
            return criaTokenJWT(id, this.expiracao);
        },
        verifica(token) {
            return verificaTokenJWT(token, this.nome, this.lista);
        },
        invalida(token) {
            return invalidaTokenJWT(token, this.lista);
        }
    },

    refresh:{
        lista: allowListRefreshToken,
        nome: 'refresh token',
        expiracao: [5, 'd'],
        cria(id) {
            return criaTokenOpaco(id, this.expiracao, this.lista);
        },
        verifica(token) {
            return verificaTokenOpaco(token, this.nome, this.lista);
        },
        invalida(token) {
            return invalidaTokenOpaco(token, this.lista);
        }
    },

    verificacaoEmail: {
        nome: 'token de verificacao de e-email',
        expiracao: [1, 'h'],
        cria(id) {
            return criaTokenJWT(id, this.expiracao);
        },
        verifica(token) {
            return verificaTokenJWT(token, this.nome);
        }
    }
}

function verificaTokenValido(id, nomeToken) {
    if (!id) {
        throw new InvalidArgumentError(`${nomeToken} inválido`);
    }
}

function verificaTokenEnviado(token, nomeToken) {
    if (!token) {
        throw new InvalidArgumentError(`${nomeToken} não enviado`);
    }
}
