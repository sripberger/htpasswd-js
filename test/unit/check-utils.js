const checkUtils = require('../../lib/check-utils');
const bcrypt = require('bcryptjs');
const sinon = require('sinon');
const hashUtils = require('../../lib/hash-utils');
const XError = require('xerror');

describe('checkUtils', function() {
	describe('::getHashType', function() {
		it('returns bcrypt for bcrypt prefixes', function() {
			expect(checkUtils.getHashType('$2$hash')).to.equal('bcrypt');
			expect(checkUtils.getHashType('$2a$hash')).to.equal('bcrypt');
			expect(checkUtils.getHashType('$2y$hash')).to.equal('bcrypt');
		});

		it('returns md5 for md5 prefixes', function() {
			expect(checkUtils.getHashType('$1$hash')).to.equal('md5');
			expect(checkUtils.getHashType('$apr1$hash')).to.equal('md5');
		});

		it('returns sha1 for sha1 prefix', function() {
			expect(checkUtils.getHashType('{SHA}hash')).to.equal('sha1');
		});

		it('returns crypt for all others', function() {
			expect(checkUtils.getHashType('hash')).to.equal('crypt');
		});
	});

	describe('::getHashFunction', function() {
		it('returns hashUtils::md5 for md5', function() {
			expect(checkUtils.getHashFunction('md5')).to.equal(hashUtils.md5);
		});

		it('returns hashUtils::crypt for crypt', function() {
			expect(checkUtils.getHashFunction('crypt')).to.equal(hashUtils.crypt);
		});

		it('returns hashUtils::sha1 for sha1', function() {
			expect(checkUtils.getHashFunction('sha1')).to.equal(hashUtils.sha1);
		});

		it('throws invalid argument for all others', function() {
			expect(() => checkUtils.getHashFunction('foo'))
				.to.throw(XError).that.satisfies((err) => {
					expect(err.code).to.equal(XError.INVALID_ARGUMENT);
					expect(err.message).to.equal('Unsupported hash type \'foo\'');
					expect(err.data).to.deep.equal({ hashType: 'foo' });
					return true;
				});
		});
	});

	describe('::createCheckFunction', function() {
		let hashFunction;

		beforeEach(function() {
			hashFunction = sinon.spy(function hashFunction() {
				return 'password-hash';
			});
			sandbox.stub(checkUtils, 'getHashFunction').returns(hashFunction);
		});

		it('gets hash function for provided hash type and returns a function', function() {
			let result = checkUtils.createCheckFunction('foo');

			expect(checkUtils.getHashFunction).to.be.calledOnce;
			expect(checkUtils.getHashFunction).to.be.calledOn(checkUtils);
			expect(checkUtils.getHashFunction).to.be.calledWith('foo');
			expect(result).to.be.a('function');
		});

		describe('returned function', function() {
			let checkFunction;

			beforeEach(function() {
				checkFunction = checkUtils.createCheckFunction('foo');
			});

			it('invokes hash function with provided password and hash', function() {
				return checkFunction('password', 'hash')
					.then(() => {
						expect(hashFunction).to.be.calledOnce;
						expect(hashFunction).to.be.calledWith('password', 'hash');
					});
			});

			it('resolves with true if hash result matches', function() {
				return checkFunction('password', 'password-hash')
					.then((result) => {
						expect(result).to.be.true;
					});
			});

			it('resolves with false otherwise', function() {
				return checkFunction('password', 'other-hash')
					.then((result) => {
						expect(result).to.be.false;
					});
			});
		});
	});

	describe('::getCheckFunction', function() {
		const createdCheckFunction = () => {};

		beforeEach(function() {
			sandbox.stub(checkUtils, 'getHashType').returns('foo');
			sandbox.stub(checkUtils, 'createCheckFunction').returns(
				createdCheckFunction
			);
		});

		it('gets the hash type for the provided hash', function() {
			checkUtils.getCheckFunction('hash');

			expect(checkUtils.getHashType).to.be.calledOnce;
			expect(checkUtils.getHashType).to.be.calledOn(checkUtils);
			expect(checkUtils.getHashType).to.be.calledWith('hash');
		});

		context('bcrypt hash type', function() {
			beforeEach(function() {
				checkUtils.getHashType.returns('bcrypt');
			});

			it('returns bcrypt::compare', function() {
				let result = checkUtils.getCheckFunction('hash');

				expect(result).to.equal(bcrypt.compare);
			});
		});

		context('other hash types', function() {
			it('returns created check function', function() {
				let result = checkUtils.getCheckFunction('hash');

				expect(checkUtils.createCheckFunction).to.be.calledOnce;
				expect(checkUtils.createCheckFunction).to.be.calledOn(checkUtils);
				expect(checkUtils.createCheckFunction).to.be.calledWith('foo');
				expect(result).to.equal(createdCheckFunction);
			});
		});
	});

	describe('::checkPassword', function() {
		it('gets and executes check function, returning result', function() {
			let checkFunction = sinon.spy(function checkFunction() {
				return 'check result';
			});
			sandbox.stub(checkUtils, 'getCheckFunction').returns(checkFunction);

			let result = checkUtils.checkPassword('password', 'hash');

			expect(checkUtils.getCheckFunction).to.be.calledOnce;
			expect(checkUtils.getCheckFunction).to.be.calledOn(checkUtils);
			expect(checkUtils.getCheckFunction).to.be.calledWith('hash');
			expect(checkFunction).to.be.calledOnce;
			expect(checkFunction).to.be.calledWith('password', 'hash');
			expect(result).to.equal('check result');
		});
	});
});
