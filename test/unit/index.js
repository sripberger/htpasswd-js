const htpasswdjs = require('../../lib');
const Htpasswd = require('../../lib/htpasswd');

describe('index', function() {
	describe('::authenticate', function() {
		it('authenticates against provided htpasswd string', function() {
			let str = 'htpasswd string';
			let username = 'username';
			let password = 'password';
			let htpasswd = new Htpasswd();
			let authResult = 'auth result';
			sandbox.stub(Htpasswd, 'parse').returns(htpasswd);
			sandbox.stub(htpasswd, 'authenticate').returns(authResult);

			let result = htpasswdjs.authenticate(str, username, password);

			expect(Htpasswd.parse).to.be.calledOnce;
			expect(Htpasswd.parse).to.be.calledOn(Htpasswd);
			expect(Htpasswd.parse).to.be.calledWith(str);
			expect(htpasswd.authenticate).to.be.calledOnce;
			expect(htpasswd.authenticate).to.be.calledOn(htpasswd);
			expect(htpasswd.authenticate).to.be.calledWith(username, password);
			expect(result).to.equal(authResult);
		});
	});
});
