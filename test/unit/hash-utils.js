const hashUtils = require('../../lib/hash-utils');
const md5 = require('apache-md5');
const crypt = require('apache-crypt');
const crypto = require('crypto');

describe('hashUtils', function() {
	describe('::md5', function() {
		it('is apache-md5 module', function() {
			expect(hashUtils.md5).to.equal(md5);
		});
	});

	describe('::crypt', function() {
		it('is apache-crypt module', function() {
			expect(hashUtils.crypt).to.equal(crypt);
		});
	});

	describe('::sha1', function() {
		it('returns prefixed base64 sha1 digest of a password', function() {
			let hash = crypto.createHash('sha1');
			sandbox.stub(crypto, 'createHash').returns(hash);
			sandbox.spy(hash, 'update');
			sandbox.spy(hash, 'digest');

			let result = hashUtils.sha1('password');

			expect(crypto.createHash).to.be.calledOnce;
			expect(crypto.createHash).to.be.calledOn(crypto);
			expect(crypto.createHash).to.be.calledWith('sha1');
			expect(hash.update).to.be.calledOnce;
			expect(hash.update).to.be.calledOn(hash);
			expect(hash.update).to.be.calledWith('password');
			expect(hash.digest).to.be.calledOnce;
			expect(hash.digest).to.be.calledOn(hash);
			expect(hash.digest).to.be.calledWith('base64');
			expect(hash.digest).to.be.calledAfter(hash.update);
			expect(result).to.equal(
				`{SHA}${hash.digest.firstCall.returnValue}`
			);
		});
	});
});
