const fse = require('fs-extra');
const Htpasswd = require('./htpasswd');

/**
 * Checks the provided username and password combination against an htpasswd
 * file or data string.
 * @param {Object} options - Authentication options.
 *   @param {String} username - Username, which may or may not exist.
 *   @param {String} password - Password, which may or may not be correct.
 *   @param {String} [file] - Absolute path to htpasswd file.
 *   @param {String} [data] - Htpasswd data string.
 * @returns {Promise<boolean>} - Will resolve with true if the username and
 *   password combination is correct. False otherwise. Will also resolve with
 *   false if any of the required arguments are missing.
 */
exports.authenticate = function(options) {
	let { username, password } = options;
	if (!username || !password) return Promise.resolve(false);
	if (!options.data && !options.file) return Promise.resolve(false);
	return Promise.resolve()
		.then(() => options.data || fse.readFile(options.file, 'utf8'))
		.then((data) => Htpasswd.parse(data).authenticate(username, password));
};

/**
 * Similar to `::authenticate`, but will force any file read or bcrypt hashing
 * to occur in a single event loop, so that the result can be returned directly
 * instead of in a promise. This should not normally be used for large files
 * and/or bcrypt hashes with large cost, as these will block execution until
 * they are finished.
 * @param {Object} options - Authentication options.
 *   @param {String} username - Username, which may or may not exist.
 *   @param {String} password - Password, which may or may not be correct.
 *   @param {String} [file] - Absolute path to htpasswd file.
 *   @param {String} [data] - Htpasswd data string.
 * @returns {boolean} - True if the username and password combination is
 *   correct. False otherwise. Will also return false if any of the required
 *   arguments are missing.
 */
exports.authenticateSync = function(options) {
	let { username, password } = options;
	if (!username || !password) return false;
	if (!options.data && !options.file) return false;
	let data = options.data || fse.readFileSync(options.file, 'utf8');
	return Htpasswd.parse(data).authenticateSync(username, password);
};
