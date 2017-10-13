const crypto = require('crypto');

exports.getHash = function(htpasswd, user) {
	let lines = htpasswd.split(/\r?\n/);
	for (let line of lines) {
		let [ lineUser, hash ] = line.split(/:(.*)/);
		if (lineUser === user && hash) return hash;
	}
	return null;
};

exports.sha1 = function(password) {
	return crypto.createHash('sha1').update(password).digest('base64');
};

exports.checkPassword = function(hash, password) {
	return `{SHA}${exports.sha1(password)}` === hash;
};
