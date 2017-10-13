const Htpasswd = require('./htpasswd');

exports.authenticate = function(str, username, password) {
	return Htpasswd.parse(str).authenticate(username, password);
};
