const htpasswdjs = require('../../lib');
const Htpasswd = require('../../lib/htpasswd');

describe('index', function() {
	describe('::authenticateSync', function() {
		it('authenticates against provided htpasswd string', function() {
			let str = 'htpasswd string';
			let username = 'username';
			let password = 'password';
			let htpasswd = new Htpasswd();
			let authResult = 'auth result';
			sandbox.stub(Htpasswd, 'parse').returns(htpasswd);
			sandbox.stub(htpasswd, 'authenticateSync').returns(authResult);

			let result = htpasswdjs.authenticateSync(str, username, password);

			expect(Htpasswd.parse).to.be.calledOnce;
			expect(Htpasswd.parse).to.be.calledOn(Htpasswd);
			expect(Htpasswd.parse).to.be.calledWith(str);
			expect(htpasswd.authenticateSync).to.be.calledOnce;
			expect(htpasswd.authenticateSync).to.be.calledOn(htpasswd);
			expect(htpasswd.authenticateSync).to.be.calledWith(username, password);
			expect(result).to.equal(authResult);
		});
	});
});
