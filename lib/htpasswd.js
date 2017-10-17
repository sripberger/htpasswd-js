const checkUtils = require('./check-utils');

class Htpasswd {
	constructor(hashes = {}) {
		this.hashes = hashes;
	}

	static parse(str) {
		let htpasswd = new Htpasswd();
		let lines = str.split(/\r?\n/);
		for (let line of lines) {
			let [ username, hash ] = line.split(/:(.*)/);
			if (hash) htpasswd.hashes[username] = hash;
		}
		return htpasswd;
	}

	getHash(username) {
		return this.hashes[username] || null;
	}

	authenticate(username, password) {
		let hash = this.getHash(username);
		if (!hash) return Promise.resolve(false);
		return checkUtils.checkPassword(password, hash);
	}

	authenticateSync(username, password) {
		let hash = this.getHash(username);
		if (!hash) return false;
		return checkUtils.checkPassword(password, hash, true);
	}
}

module.exports = Htpasswd;
