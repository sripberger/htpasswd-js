const Htpasswd = require('../../lib/htpasswd');
const checkUtils = require('../../lib/check-utils');

describe('Htpasswd', function() {
	it('stores provided map of hashes by username', function() {
		let hashes = {
			foo: 'Foo-Hash',
			bar: 'Bar-Hash'
		};

		let htpasswd = new Htpasswd(hashes);

		expect(htpasswd.hashes).to.equal(hashes);
	});

	it('deaults to empty hashes map', function() {
		let htpasswd = new Htpasswd();

		expect(htpasswd.hashes).to.deep.equal({});
	});

	describe('::parse', function() {
		const str = 'foo:Foo-Hash\nbar:Bar-Hash\nbaz:Baz-Hash\n';

		it('returns an instance parsed from provided string', function() {
			let result = Htpasswd.parse(str);

			expect(result).to.be.an.instanceof(Htpasswd);
			expect(result.hashes).to.deep.equal({
				foo: 'Foo-Hash',
				bar: 'Bar-Hash',
				baz: 'Baz-Hash'
			});
		});

		it('supports Windows-style line endings', function() {
			let result = Htpasswd.parse(str.replace(/\n/g, '\r\n'));

			expect(result).to.be.an.instanceof(Htpasswd);
			expect(result.hashes).to.deep.equal({
				foo: 'Foo-Hash',
				bar: 'Bar-Hash',
				baz: 'Baz-Hash'
			});
		});

		it('supports colons in hashes', function() {
			let result = Htpasswd.parse(str.replace(/-/g, ':'));

			expect(result).to.be.an.instanceof(Htpasswd);
			expect(result.hashes).to.deep.equal({
				foo: 'Foo:Hash',
				bar: 'Bar:Hash',
				baz: 'Baz:Hash'
			});
		});
	});

	describe('#getHash', function() {
		let htpasswd;

		beforeEach(function() {
			htpasswd = new Htpasswd({
				foo: 'Foo-Hash',
				bar: 'Bar-Hash',
				baz: 'Baz-Hash'
			});
		});

		it('returns the hash for the provided username', function() {
			expect(htpasswd.getHash('foo')).to.equal('Foo-Hash');
			expect(htpasswd.getHash('bar')).to.equal('Bar-Hash');
			expect(htpasswd.getHash('baz')).to.equal('Baz-Hash');
		});

		it('returns null if hash is not found', function() {
			expect(htpasswd.getHash('qux')).to.be.null;
		});
	});

	describe('#authenticateSync', function() {
		const username = 'username';
		const password = 'password';
		const hash = 'hash';
		const checkResult = 'check result';
		let htpasswd;

		beforeEach(function() {
			htpasswd = new Htpasswd();
			sandbox.stub(htpasswd, 'getHash').returns(hash);
			sandbox.stub(checkUtils, 'checkPassword').returns(checkResult);
		});

		it('authenticates provided username and password', function() {
			let result = htpasswd.authenticateSync(username, password);

			expect(htpasswd.getHash).to.be.calledOnce;
			expect(htpasswd.getHash).to.be.calledOn(htpasswd);
			expect(htpasswd.getHash).to.be.calledWith(username);
			expect(checkUtils.checkPassword).to.be.calledOnce;
			expect(checkUtils.checkPassword).to.be.calledOn(checkUtils);
			expect(checkUtils.checkPassword).to.be.calledWith(password, hash, true);
			expect(result).to.equal(checkResult);
		});

		it('returns false without checking if hash is not found for user', function() {
			htpasswd.getHash.returns(null);

			let result = htpasswd.authenticateSync(username, password);

			expect(checkUtils.checkPassword).to.not.be.called;
			expect(result).to.be.false;
		});
	});
});
