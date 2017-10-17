const htpasswd = require('../../lib');
const fse = require('fs-extra');
const path = require('path');

describe('htpasswd-js', function() {
	const dataPath = path.resolve(__dirname, '../data/test.htpasswd');
	let data;

	before(function() {
		data = fse.readFileSync(dataPath, 'utf8');
	});

	describe('::authenticate', function() {
		it('works with bcrypt', function() {
			return Promise.all([
				htpasswd.authenticate(data, 'bcrypt', 'password'),
				htpasswd.authenticate(data, 'bcrypt', 'other')
			])
				.then(([ result, otherResult ]) => {
					expect(result).to.be.true;
					expect(otherResult).to.be.false;
				});
		});

		it('works with md5', function() {
			return Promise.all([
				htpasswd.authenticate(data, 'md5', 'password'),
				htpasswd.authenticate(data, 'md5', 'other')
			])
				.then(([ result, otherResult ]) => {
					expect(result).to.be.true;
					expect(otherResult).to.be.false;
				});
		});

		it('works with sha1', function() {
			return Promise.all([
				htpasswd.authenticate(data, 'sha1', 'password'),
				htpasswd.authenticate(data, 'sha1', 'other')
			])
				.then(([ result, otherResult ]) => {
					expect(result).to.be.true;
					expect(otherResult).to.be.false;
				});
		});

		it('works with crypt(3)', function() {
			return Promise.all([
				htpasswd.authenticate(data, 'crypt', 'password'),
				htpasswd.authenticate(data, 'crypt', 'other')
			])
				.then(([ result, otherResult ]) => {
					expect(result).to.be.true;
					expect(otherResult).to.be.false;
				});
		});
	});

	describe('::authenticateSync', function() {
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
});
