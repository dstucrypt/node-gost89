'use strict';
var binding = require('../build/Release/binding');

var Gost = function () {
    this.ctx = binding.init();
};

Gost.prototype.key = function (key) {
    this.ctx.key(key);
};

Gost.prototype.crypt = function (data, out) {
    this.ctx.crypt(data, out, 0);
};

Gost.prototype.decrypt = function (data, out) {
    this.ctx.crypt(data, out, 1);
};

Gost.prototype.crypt_cfb = function (iv, data, out) {
    var blocks = Math.ceil(data.length  / 8);
    if (!out) {
        out = new Buffer(blocks * 8, 'binary');
    }
    if (!Buffer.isBuffer(out)) {
        throw new Error("Either pass output buffer or nothing");
    }

    if (!Buffer.isBuffer(data)) {
        data = new Buffer(data, 'binary');
    }

    if (data.length !== (blocks * 8)) {
        var _data = new Buffer(blocks * 8);
        data.copy(_data);
        data = _data;
    }

    if (!Buffer.isBuffer(iv)) {
        iv = new Buffer(iv, 'binary');
    }

    this.ctx.crypt(data, out, 2, iv);

    return out;
};

Gost.prototype.mac = function (bits, data, rbuf) {
    rbuf = rbuf || new Buffer(bits / 8);
    this.ctx.mac(data, rbuf, bits);
    return rbuf;
};

Gost.prototype.decrypt_cfb = function (iv, data, out) {
    var blocks = Math.ceil(data.length  / 8);

    if (!out) {
        out = new Buffer(blocks * 8, 'binary');
    }
    if (!Buffer.isBuffer(out)) {
        throw new Error("Either pass output buffer or nothing");
    }

    if (!Buffer.isBuffer(data)) {
        data = new Buffer(data, 'binary');
    }

    if (data.length !== (blocks * 8)) {
        var _data = new Buffer(blocks * 8);
        data.copy(_data);
        data = _data;
    }

    if (!Buffer.isBuffer(iv)) {
        iv = new Buffer(iv, 'binary');
    }

    this.ctx.crypt(data, out, 3, iv);

    return out;
};

Gost.init = function () {
    return new Gost();
};

module.exports = Gost;
