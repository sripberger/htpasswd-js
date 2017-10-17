const htpasswd = require('../../lib');
const path = require('path');

describe('htpasswd-js', function() {
	const file = path.resolve(__dirname, '../data/test.htpasswd');

	it('works with bcrypt', function() {
		return Promise.all([
			htpasswd.authenticate({
				username: 'bcrypt',
				password: 'password',
				file
			}),
			htpasswd.authenticate({
				username: 'bcrypt',
				password: 'other',
				file
			})
		])
			.then(([ result, otherResult ]) => {
				expect(result).to.be.true;
				expect(otherResult).to.be.false;
			});
	});

	it('works with md5', function() {
		return Promise.all([
			htpasswd.authenticate({
				username: 'md5',
				password: 'password',
				file
			}),
			htpasswd.authenticate({
				username: 'md5',
				password: 'other',
				file
			})
		])
			.then(([ result, otherResult ]) => {
				expect(result).to.be.true;
				expect(otherResult).to.be.false;
			});
	});

	it('works with sha1', function() {
		return Promise.all([
			htpasswd.authenticate({
				username: 'sha1',
				password: 'password',
				file
			}),
			htpasswd.authenticate({
				username: 'sha1',
				password: 'other',
				file
			})
		])
			.then(([ result, otherResult ]) => {
				expect(result).to.be.true;
				expect(otherResult).to.be.false;
			});
	});

	it('works with crypt(3)', function() {
		return Promise.all([
			htpasswd.authenticate({
				username: 'crypt',
				password: 'password',
				file
			}),
			htpasswd.authenticate({
				username: 'crypt',
				password: 'other',
				file
			})
		])
			.then(([ result, otherResult ]) => {
				expect(result).to.be.true;
				expect(otherResult).to.be.false;
			});
	});
});
