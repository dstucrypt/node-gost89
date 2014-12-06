var binding = require('./build/Release/binding');

module.exports.gosthash = function(str_input) {
  var b = new Buffer(str_input, 'binary'),
      out = new Buffer(32);
  binding.gosthash(b, out);
  return out;
};

var Hash = function () {
    this.ctx = binding.hashinit();
};

Hash.prototype.update = function (data) {
    if (!Buffer.isBuffer(data)) {
        data = new Buffer(data, 'binary');
    }

    this.ctx.update(data);
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
    this.ctx.crypt(data, out, 2, iv);
};

Gost.prototype.decrypt_cfb = function (iv, data, out) {
    this.ctx.crypt(data, out, 3, iv);
};

Gost.init = function () {
    return new Gost();
};

module.exports.Hash = {
    init: Hash.init,
};
module.exports.init = Gost.init;
