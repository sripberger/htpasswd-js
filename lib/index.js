const Htpasswd = require('./htpasswd');

exports.authenticateSync = function(str, username, password) {
	return Htpasswd.parse(str).authenticateSync(username, password);
};
