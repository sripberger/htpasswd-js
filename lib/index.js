const utils = require('./utils');

exports.authenticate = function(htpasswd, username, password) {
	let hash = utils.getHash(htpasswd, username);
	return !!hash && utils.checkPassword(hash, password);
};
