const crypto = require('crypto');

exports.sha1 = function(password) {
	return crypto.createHash('sha1').update(password).digest('base64');
};

exports.md5 = require('apache-md5');

exports.checkPassword = function(hash, password) {
	if (hash.startsWith('{SHA}')) {
		return `{SHA}${exports.sha1(password)}` === hash;
	}

	return exports.md5(password, hash) === hash;
};
