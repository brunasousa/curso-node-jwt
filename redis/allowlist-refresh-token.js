const redis = require('redis');
const manipulaLista = require('./manupula-lista')
const allowList = redis.createClient({ prefix: 'allowlist-refresh-token:', legacyMode: true });
allowList.connect();
module.exports = manipulaLista(allowList);
