const bcrypt = require('bcryptjs');
const hashUtils = require('./hash-utils');

exports.checkPassword = function(hash, password) {
	if (/^\$2.?\$/.test(hash)) return bcrypt.compareSync(password, hash);
	if (/^\$apr1\$/.test(hash)) return hashUtils.md5(password, hash) === hash;
	if (/^\{SHA\}/.test(hash)) return hashUtils.sha1(password) === hash;
	return hashUtils.crypt(password, hash) === hash;
};
