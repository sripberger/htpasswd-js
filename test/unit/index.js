const htpasswdjs = require('../../lib');
const Htpasswd = require('../../lib/htpasswd');

describe('index', function() {
	const str = 'htpasswd string';
	const username = 'username';
	const password = 'password';
	const authResult = 'auth result';
	let htpasswd;

	beforeEach(function() {
		htpasswd = new Htpasswd();
		sandbox.stub(Htpasswd, 'parse').returns(htpasswd);
	});

	describe('::authenticate', function() {
		it('asynchronously authenticates against provided htpasswd string', function() {
			sandbox.stub(htpasswd, 'authenticate').resolves(authResult);

			return htpasswdjs.authenticate(str, username, password)
				.then((result) => {
					expect(Htpasswd.parse).to.be.calledOnce;
					expect(Htpasswd.parse).to.be.calledOn(Htpasswd);
					expect(Htpasswd.parse).to.be.calledWith(str);
					expect(htpasswd.authenticate).to.be.calledOnce;
					expect(htpasswd.authenticate).to.be.calledOn(htpasswd);
					expect(htpasswd.authenticate).to.be.calledWith(
						username,
						password
					);
					expect(result).to.equal(authResult);
				});
		});
	});

	describe('::authenticateSync', function() {
		it('synchronously authenticates against provided htpasswd string', function() {
			sandbox.stub(htpasswd, 'authenticateSync').returns(authResult);

			let result = htpasswdjs.authenticateSync(str, username, password);

			expect(Htpasswd.parse).to.be.calledOnce;
			expect(Htpasswd.parse).to.be.calledOn(Htpasswd);
			expect(Htpasswd.parse).to.be.calledWith(str);
			expect(htpasswd.authenticateSync).to.be.calledOnce;
			expect(htpasswd.authenticateSync).to.be.calledOn(htpasswd);
			expect(htpasswd.authenticateSync).to.be.calledWith(
				username,
				password
			);
			expect(result).to.equal(authResult);
		});
	});
});
