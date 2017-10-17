const Htpasswd = require('./htpasswd');

exports.authenticate = function(str, username, password) {
	return Htpasswd.parse(str).authenticate(username, password);
};

exports.authenticateSync = function(str, username, password) {
	return Htpasswd.parse(str).authenticateSync(username, password);
};
