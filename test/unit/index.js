const htpasswdjs = require('../../lib');
const fse = require('fs-extra');
const Htpasswd = require('../../lib/htpasswd');

describe('index', function() {
	const file = 'path/to/htpasswd/file';
	const data = 'htpasswd data string';
	const username = 'username';
	const password = 'password';
	const authResult = 'auth result';
	let htpasswd;

	beforeEach(function() {
		htpasswd = new Htpasswd();
		sandbox.stub(fse, 'readFile').resolves(data);
		sandbox.stub(fse, 'readFileSync').returns(data);
		sandbox.stub(Htpasswd, 'parse').returns(htpasswd);
	});

	describe('::authenticate', function() {
		beforeEach(function() {
			sandbox.stub(htpasswd, 'authenticate').resolves(authResult);
		});

		it('authenticates against provided htpasswd file', function() {
			return htpasswdjs.authenticate({ username, password, file })
				.then((result) => {
					expect(fse.readFile).to.be.calledOnce;
					expect(fse.readFile).to.be.calledOn(fse);
					expect(fse.readFile).to.be.calledWith(file, 'utf8');
					expect(Htpasswd.parse).to.be.calledOnce;
					expect(Htpasswd.parse).to.be.calledOn(Htpasswd);
					expect(Htpasswd.parse).to.be.calledWith(data);
					expect(htpasswd.authenticate).to.be.calledOnce;
					expect(htpasswd.authenticate).to.be.calledOn(htpasswd);
					expect(htpasswd.authenticate).to.be.calledWith(
						username,
						password
					);
					expect(result).to.equal(authResult);
				});
		});

		it('authenticates against provided htpasswd data', function() {
			return htpasswdjs.authenticate({ username, password, data })
				.then((result) => {
					expect(fse.readFile).to.not.be.called;
					expect(Htpasswd.parse).to.be.calledOnce;
					expect(Htpasswd.parse).to.be.calledOn(Htpasswd);
					expect(Htpasswd.parse).to.be.calledWith(data);
					expect(htpasswd.authenticate).to.be.calledOnce;
					expect(htpasswd.authenticate).to.be.calledOn(htpasswd);
					expect(htpasswd.authenticate).to.be.calledWith(
						username,
						password
					);
					expect(result).to.equal(authResult);
				});
		});

		it('resolves with false if neither file nor data are provided', function() {
			return htpasswdjs.authenticate({ username, password })
				.then((result) => {
					expect(fse.readFile).to.not.be.called;
					expect(Htpasswd.parse).to.not.be.called;
					expect(result).to.be.false;
				});
		});

		it('resolves with false if username is missing', function() {
			return Promise.all([
				htpasswdjs.authenticate({ password, file }),
				htpasswdjs.authenticate({ password, data })
			])
				.then(([ result, otherResult ]) => {
					expect(fse.readFile).to.not.be.called;
					expect(Htpasswd.parse).to.not.be.called;
					expect(result).to.be.false;
					expect(otherResult).to.be.false;
				});
		});

		it('resolves with false if password is missing', function() {
			return Promise.all([
				htpasswdjs.authenticate({ username, file }),
				htpasswdjs.authenticate({ username, data })
			])
				.then(([ result, otherResult ]) => {
					expect(fse.readFile).to.not.be.called;
					expect(Htpasswd.parse).to.not.be.called;
					expect(result).to.be.false;
					expect(otherResult).to.be.false;
				});
		});
	});

	describe('::authenticateSync', function() {
		beforeEach(function() {
			sandbox.stub(htpasswd, 'authenticateSync').returns(authResult);
		});

		it('authenticates against provided htpasswd file', function() {
			let result = htpasswdjs.authenticateSync({
				username,
				password,
				file
			});

			expect(fse.readFileSync).to.be.calledOnce;
			expect(fse.readFileSync).to.be.calledOn(fse);
			expect(fse.readFileSync).to.be.calledWith(file, 'utf8');
			expect(Htpasswd.parse).to.be.calledOnce;
			expect(Htpasswd.parse).to.be.calledOn(Htpasswd);
			expect(Htpasswd.parse).to.be.calledWith(data);
			expect(htpasswd.authenticateSync).to.be.calledOnce;
			expect(htpasswd.authenticateSync).to.be.calledOn(htpasswd);
			expect(htpasswd.authenticateSync).to.be.calledWith(
				username,
				password
			);
			expect(result).to.equal(authResult);
		});

		it('authenticates against provided htpasswd data', function() {
			let result = htpasswdjs.authenticateSync({
				username,
				password,
				data
			});

			expect(fse.readFileSync).to.not.be.called;
			expect(Htpasswd.parse).to.be.calledOnce;
			expect(Htpasswd.parse).to.be.calledOn(Htpasswd);
			expect(Htpasswd.parse).to.be.calledWith(data);
			expect(htpasswd.authenticateSync).to.be.calledOnce;
			expect(htpasswd.authenticateSync).to.be.calledOn(htpasswd);
			expect(htpasswd.authenticateSync).to.be.calledWith(
				username,
				password
			);
			expect(result).to.equal(authResult);
		});

		it('returns false if neither file nor data are provided', function() {
			let result = htpasswdjs.authenticateSync({ username, password });

			expect(fse.readFileSync).to.not.be.called;
			expect(Htpasswd.parse).to.not.be.called;
			expect(result).to.be.false;
		});

		it('returns false if username is missing', function() {
			let result = htpasswdjs.authenticateSync({ username, file });
			let otherResult = htpasswdjs.authenticateSync({ username, data });

			expect(fse.readFileSync).to.not.be.called;
			expect(Htpasswd.parse).to.not.be.called;
			expect(result).to.be.false;
			expect(otherResult).to.be.false;
		});

		it('returns false if password is missing', function() {
			let result = htpasswdjs.authenticateSync({ password, file });
			let otherResult = htpasswdjs.authenticateSync({ password, data });

			expect(fse.readFileSync).to.not.be.called;
			expect(Htpasswd.parse).to.not.be.called;
			expect(result).to.be.false;
			expect(otherResult).to.be.false;
		});
	});
});
