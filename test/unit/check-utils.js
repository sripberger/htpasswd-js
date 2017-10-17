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

	describe('::getSyncCheckFunction', function() {
		let hashFunction;

		beforeEach(function() {
			hashFunction = sinon.spy(function hashFunction() {
				return 'password-hash';
			});
			sandbox.stub(checkUtils, 'getHashFunction').returns(hashFunction);
		});

		it('gets hash function for provided hash type and returns a function', function() {
			let result = checkUtils.getSyncCheckFunction('foo');

			expect(checkUtils.getHashFunction).to.be.calledOnce;
			expect(checkUtils.getHashFunction).to.be.calledOn(checkUtils);
			expect(checkUtils.getHashFunction).to.be.calledWith('foo');
			expect(result).to.be.a('function');
		});

		describe('returned function', function() {
			let checkFunction;

			beforeEach(function() {
				checkFunction = checkUtils.getSyncCheckFunction('foo');
			});

			it('invokes hash function with provided password and hash', function() {
				checkFunction('password', 'hash');

				expect(hashFunction).to.be.calledOnce;
				expect(hashFunction).to.be.calledWith('password', 'hash');
			});

			it('returns true if hash result matches', function() {
				expect(checkFunction('password', 'password-hash')).to.be.true;
			});

			it('returns false otherwise', function() {
				expect(checkFunction('password', 'other-hash')).to.be.false;
			});
		});
	});

	describe('::getAsyncCheckFunction', function() {
		let syncCheckFunction;

		beforeEach(function() {
			syncCheckFunction = sinon.spy(function syncCheckFunction() {
				return 'check result';
			});
			sandbox.stub(checkUtils, 'getSyncCheckFunction').returns(syncCheckFunction);
		});

		it('gets a synchronous check function for the provided type and returns a function', function() {
			let result = checkUtils.getAsyncCheckFunction('foo');

			expect(checkUtils.getSyncCheckFunction).to.be.calledOnce;
			expect(checkUtils.getSyncCheckFunction).to.be.calledOn(checkUtils);
			expect(checkUtils.getSyncCheckFunction).to.be.calledWith('foo');
			expect(result).to.be.a('function');
		});

		describe('returned function', function() {
			let asyncCheckFunction;

			beforeEach(function() {
				asyncCheckFunction = checkUtils.getAsyncCheckFunction('foo');
			});

			it('wraps synchronous check function in a promise', function() {
				return asyncCheckFunction('password', 'hash')
					.then((result) => {
						expect(syncCheckFunction).to.be.calledOnce;
						expect(syncCheckFunction).to.be.calledWith('password', 'hash');
						expect(result).to.equal('check result');
					});
			});
		});
	});

	describe('::getCheckFunction', function() {
		const syncCheckFunction = () => {};
		const asyncCheckFunction = () => {};

		beforeEach(function() {
			sandbox.stub(checkUtils, 'getHashType').returns('foo');
			sandbox.stub(checkUtils, 'getSyncCheckFunction').returns(
				syncCheckFunction
			);
			sandbox.stub(checkUtils, 'getAsyncCheckFunction').returns(
				asyncCheckFunction
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
			it('returns asynchronous check function', function() {
				let result = checkUtils.getCheckFunction('hash');

				expect(checkUtils.getAsyncCheckFunction).to.be.calledOnce;
				expect(checkUtils.getAsyncCheckFunction).to.be.calledOn(checkUtils);
				expect(checkUtils.getAsyncCheckFunction).to.be.calledWith('foo');
				expect(result).to.equal(asyncCheckFunction);
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
