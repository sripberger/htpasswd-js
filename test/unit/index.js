const htpasswd = require('../../lib');
const utils = require('../../lib/utils');

describe('index', function() {
	describe('authenticate', function() {
		const username = 'username';
		const password = 'password';
		const htpasswdStr = 'htpasswd string';
		const hash = 'hash';
		const checkResult = 'check result';

		beforeEach(function() {
			sandbox.stub(utils, 'getHash').returns(hash);
			sandbox.stub(utils, 'checkPassword').returns(checkResult);
		});

		it('authenticates against provided htpasswd string', function() {
			let result = htpasswd.authenticate(htpasswdStr, username, password);

			expect(utils.getHash).to.be.calledOnce;
			expect(utils.getHash).to.be.calledOn(utils);
			expect(utils.getHash).to.be.calledWith(htpasswdStr, username);
			expect(utils.checkPassword).to.be.calledOnce;
			expect(utils.checkPassword).to.be.calledOn(utils);
			expect(utils.checkPassword).to.be.calledWith(hash, password);
			expect(result).to.equal(checkResult);
		});

		it('returns false without checking if hash is not found for user', function() {
			utils.getHash.returns(null);

			let result = htpasswd.authenticate(htpasswdStr, username, password);

			expect(utils.checkPassword).to.not.be.called;
			expect(result).to.be.false;
		});
	});
});
