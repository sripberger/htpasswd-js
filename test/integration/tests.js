const htpasswd = require('../../lib');
const fse = require('fs-extra');
const path = require('path');

describe('htpasswd-js', function() {
	const dataPath = path.resolve(__dirname, '../data/test.htpasswd');
	let data;

	before(function() {
		data = fse.readFileSync(dataPath, 'utf8');
	});

	it('works with bcrypt', function() {
		expect(htpasswd.authenticateSync(data, 'bcrypt', 'password')).to.be.true;
		expect(htpasswd.authenticateSync(data, 'bcrypt', 'other')).to.be.false;
	});

	it('works with md5', function() {
		expect(htpasswd.authenticateSync(data, 'md5', 'password')).to.be.true;
		expect(htpasswd.authenticateSync(data, 'md5', 'other')).to.be.false;
	});

	it('works with sha1', function() {
		expect(htpasswd.authenticateSync(data, 'sha1', 'password')).to.be.true;
		expect(htpasswd.authenticateSync(data, 'sha1', 'other')).to.be.false;
	});

	it('works with crypt(3)', function() {
		expect(htpasswd.authenticateSync(data, 'crypt', 'password')).to.be.true;
		expect(htpasswd.authenticateSync(data, 'crypt', 'other')).to.be.false;
	});
});
