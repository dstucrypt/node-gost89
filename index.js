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

module.exports.Hash = {
    init: Hash.init,
};
