const crypto = require('crypto');
const bcrypt = require('bcryptjs');

exports.md5 = require('apache-md5');
exports.crypt = require('apache-crypt');

exports.sha1 = function(password) {
	return crypto.createHash('sha1').update(password).digest('base64');
};

exports.checkPassword = function(hash, password) {
	if (hash.startsWith('{SHA}')) {
		return `{SHA}${exports.sha1(password)}` === hash;
	}
	if (hash.startsWith('$apr1$')) return exports.md5(password, hash) === hash;
	if (/^\$2.?\$/.test(hash)) return bcrypt.compareSync(password, hash);
	return exports.crypt(password, hash) === hash;
};
