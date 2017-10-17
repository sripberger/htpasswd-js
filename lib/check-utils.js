const bcrypt = require('bcryptjs');
const hashUtils = require('./hash-utils');
const XError = require('xerror');

/**
 * Utility functions for checking passwords against hashes.
 * @name checkUtils
 * @kind module
 * @private
 */

 /**
  * Examines the prefix of a hash string to determine its type.
  * @memberof checkUtils
  * @param {String} hash - Hash string from htpasswd
  * @returns {String} - 'bcrypt', 'md5', 'sha1' or 'crypt'.
  */
exports.getHashType = function(hash) {
	if (/^\$2.?\$/.test(hash)) return 'bcrypt';
	if (/^\$(apr)?1\$/.test(hash)) return 'md5';
	if (/^\{SHA\}/.test(hash)) return 'sha1';
	return 'crypt';
};

/**
 * Gets a password hashing function for the provided hash type. `bcrypt` is not
 * supported, because the bcryptjs library already provides password-checking
 * functions, so performing bcrypt hashes ourselves is not necessary.
 * @memberof checkUtils
 * @param {String} hashType - 'md5', 'sha1', or 'crypt'
 * @returns {Function} - Accepts two arguments-- password and hash. The hash
 *   argument contains the salt, if any is to be used.
 */
exports.getHashFunction = function(hashType) {
	let fn = hashUtils[hashType];
	if (fn) return fn;
	throw new XError(
		XError.INVALID_ARGUMENT,
		`Unsupported hash type '${hashType}'`,
		{ hashType }
	);
};

/**
 * Gets a password-checking function for the provided hash type. 'bcrypt' is
 * not supported, because the bcryptjs library already provides password-
 * checking functions, so creating them ourselves is not necessary.
 * @memberof checkUtils
 * @param {String} hashType - 'md5', 'sha1', or 'crypt'
 * @returns {Function} - Accepts two arguments-- password and hash. Will return
 *   true if the password is correct, false otherwise.
 */
exports.getSyncCheckFunction = function(hashType) {
	let hashFunction = exports.getHashFunction(hashType);
	return (password, hash) => hashFunction(password, hash) === hash;
};

/**
 * Gets a password-checking function for the provided hash type, wrapping the
 * result in a promise. This is to provide a consistent asynchronous interface,
 * even though actual asynchronous code will only occur in the case of 'bcrypt'.
 * 'bcrypt' itself is not supported here, because the bcryptjs library already
 * provides an asynchronous password-checking function, so creating it ourselves
 * is not necessary.
 * @memberof checkUtils
 * @param {String} hashType - 'md5', 'sha1', or 'crypt'
 * @returns {Function} - Accepts two arguments-- password and hash. Returns
 *   a promise that will resolve with true if the password is correct, or false
 *   otherwise.
 */
exports.getAsyncCheckFunction = function(hashType) {
	let checkFunction = exports.getSyncCheckFunction(hashType);
	return (password, hash) => Promise.resolve(checkFunction(password, hash));
};

/**
 * Gets a password-checking function for the provided hash, with bcrypt support.
 * @memberof checkUtils
 * @param {String} hash - Hash string from htpasswd.
 * @param {boolean} [sync=false] - If true, the returned function will be
 *   synchronous, forcing bcrypt checks to occur on a single event loop.
 * @returns {Function} - Accepts two arguments-- password and hash. Returns
 *   a promise that will resolve with true if the password is correct, or false
 *   otherwise. If the `sync` argument was true, this function will return its
 *   result directly, instead of returning a promise.
 */
exports.getCheckFunction = function(hash, sync = false) {
	let hashType = exports.getHashType(hash);
	if (hashType === 'bcrypt') {
		return (sync) ? bcrypt.compareSync : bcrypt.compare;
	}
	if (sync) return exports.getSyncCheckFunction(hashType);
	return exports.getAsyncCheckFunction(hashType);
};

/**
 * Checks a password against the provided hash.
 * @memberof checkUtils
 * @param {String} password - Password to check.
 * @param {String} hash - Hash string from htpasswd.
 * @param {boolean} [sync=false] - If true, this function will be synchronous,
 *   forcing bcrypt checks to be performed in a single event loop.
 * @returns {Promise<boolean>|boolean} - Will resolve with true if the password
 *   was correct, false otherwise. If the `sync` argument was true, this result
 *   will be returned directly instead of in a promise.
 */
exports.checkPassword = function(password, hash, sync) {
	let checkFunction = exports.getCheckFunction(hash, sync);
	return checkFunction(password, hash);
};
