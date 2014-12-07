'use strict';
var binding = require('./build/Release/binding');
var Hash = require('./lib/hash.js'),
    Gost = require('./lib/gost89'),
    compat = require('./lib/compat.js'),
    util = require('./lib/util.js'),
    keywrap = require('./lib/keywrap.js');

module.exports = {
    Hash: Hash,
    gosthash: Hash.gosthash,
    init: Gost.init,
    dumb_kdf: util.dumb_kdf,
    pbkdf: util.pbkdf,
    unwrap_key: keywrap.unwrap,
    wrap_key: keywrap.wrap,
    compat: compat,
};
