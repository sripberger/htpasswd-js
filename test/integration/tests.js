const htpasswd = require('../../lib');
const fse = require('fs-extra');
const path = require('path');

describe('htpasswd-js', function() {
	it('works with sha1', function() {
		let file = path.resolve(__dirname, '../data/test.htpasswd');
		let str = fse.readFileSync(file, 'utf8');

		expect(htpasswd.authenticate(str, 'sha1', 'password')).to.be.true;
		expect(htpasswd.authenticate(str, 'sha1', 'other')).to.be.false;
	});
});
