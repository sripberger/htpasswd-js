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

	authenticateSync(username, password) {
		let hash = this.getHash(username);
		return !!hash && checkUtils.checkPassword(password, hash, true);
	}
}

module.exports = Htpasswd;
