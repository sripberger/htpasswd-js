const fse = require('fs-extra');
const Htpasswd = require('./htpasswd');

exports.authenticate = function(options) {
	let { username, password } = options;
	return Promise.resolve()
		.then(() => options.data || fse.readFile(options.file, 'utf8'))
		.then((data) => Htpasswd.parse(data).authenticate(username, password));
};

exports.authenticateSync = function(options) {
	let { username, password } = options;
	let data = options.data || fse.readFileSync(options.file, 'utf8');
	return Htpasswd.parse(data).authenticateSync(username, password);
};
