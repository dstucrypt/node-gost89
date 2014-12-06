var binding = require('./build/Release/binding');

module.exports.gosthash = function(str_input) {
  var b = new Buffer(str_input, 'binary'),
      out = new Buffer(32);
  binding.gosthash(b, out);
  return out;
};
