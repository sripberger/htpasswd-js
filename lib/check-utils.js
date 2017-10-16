const bcrypt = require('bcryptjs');
const hashUtils = require('./hash-utils');
const XError = require('xerror');

exports.getHashType = function(hash) {
	if (/^\$2.?\$/.test(hash)) return 'bcrypt';
	if (/^\$(apr)?1\$/.test(hash)) return 'md5';
	if (/^\{SHA\}/.test(hash)) return 'sha1';
	return 'crypt';
};

exports.getHashFunction = function(hashType) {
	let fn = hashUtils[hashType];
	if (fn) return fn;
	throw new XError(
		XError.INVALID_ARGUMENT,
		`Unsupported hash type '${hashType}'`,
		{ hashType }
	);
};

exports.getSyncCheckFunction = function(hashType) {
	let hashFunction = exports.getHashFunction(hashType);
	return (password, hash) => hashFunction(password, hash) === hash;
};

exports.getAsyncCheckFunction = function(hashType) {
	let checkFunction = exports.getSyncCheckFunction(hashType);
	return (password, hash) => Promise.resolve(checkFunction(password, hash));
};

exports.getCheckFunction = function(hash, sync = false) {
	let hashType = exports.getHashType(hash);
	if (hashType === 'bcrypt') {
		return (sync) ? bcrypt.compareSync : bcrypt.compare;
	}
	if (sync) return exports.getSyncCheckFunction(hashType);
	return exports.getAsyncCheckFunction(hashType);
};

exports.checkPassword = function(password, hash, sync) {
	let checkFunction = exports.getCheckFunction(hash, sync);
	return checkFunction(password, hash);
};
