const htpasswd = require('../../lib');
const fse = require('fs-extra');
const path = require('path');

describe('htpasswd-js', function() {
	const dataPath = path.resolve(__dirname, '../data/test.htpasswd');
	let data;

	before(function() {
		data = fse.readFileSync(dataPath, 'utf8');
	});

	it('works with sha1', function() {
		expect(htpasswd.authenticate(data, 'sha1', 'password')).to.be.true;
		expect(htpasswd.authenticate(data, 'sha1', 'other')).to.be.false;
	});
});