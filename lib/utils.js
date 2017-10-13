const crypto = require('crypto');

exports.sha1 = function(password) {
	return crypto.createHash('sha1').update(password).digest('base64');
};

exports.checkPassword = function(hash, password) {
	return `{SHA}${exports.sha1(password)}` === hash;
};
