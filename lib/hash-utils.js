const crypto = require('crypto');

exports.md5 = require('apache-md5');
exports.crypt = require('apache-crypt');

exports.sha1 = function(password) {
	let hash = crypto.createHash('sha1').update(password);
	return `{SHA}${hash.digest('base64')}`;
};
