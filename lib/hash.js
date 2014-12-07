'use strict';
var binding = require('../build/Release/binding');

var Hash = function () {
    this.ctx = binding.hashinit();
};

Hash.prototype.update = function (data) {
    if (!Buffer.isBuffer(data)) {
        data = new Buffer(data, 'binary');
    }

    this.ctx.update(data);
};

Hash.prototype.update32 = function (data) {
    this.ctx.update(data);
};

Hash.prototype.reset = function () {
    this.ctx.reset();
};

Hash.prototype.finish = function (data) {
    if (!data) {
        data = new Buffer(32);
    }
    this.ctx.finish(data);
    return data;
};

Hash.init = function () {
    return new Hash();
};

var gosthash = function(data) {
    var ctx = Hash.init();
    if (typeof data === 'string') {
        data = new Buffer(data, 'binary');
    }
    ctx.update(data);
    return ctx.finish();
};

module.exports = Hash;
module.exports.gosthash = gosthash;
