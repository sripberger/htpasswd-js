const utils = require('../../lib/utils');
const crypto = require('crypto');
const md5 = require('apache-md5');
const crypt = require('apache-crypt');
const bcrypt = require('bcryptjs');

describe('utils', function() {
	describe('::md5', function() {
		it('is apache-md5 module', function() {
			expect(utils.md5).to.equal(md5);
		});
	});

	describe('::crypt', function() {
		it('is apache-crypt module', function() {
			expect(utils.crypt).to.equal(crypt);
		});
	});

	describe('::sha1', function() {
		it('returns prefixed base64 sha1 digest of a password', function() {
			let hash = crypto.createHash('sha1');
			sandbox.stub(crypto, 'createHash').returns(hash);
			sandbox.spy(hash, 'update');
			sandbox.spy(hash, 'digest');

			let result = utils.sha1('password');

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

	describe('::checkPassword', function() {
		const password = 'password';

		context('sha1', function() {
			const hash = '{SHA}correct-hash';

			beforeEach(function() {
				sandbox.stub(utils, 'sha1');
			});

			it('hashes password with ::sha1', function() {
				utils.checkPassword(hash, password);

				expect(utils.sha1).to.be.calledOnce;
				expect(utils.sha1).to.be.calledOn(utils);
				expect(utils.sha1).to.be.calledWith(password);
			});

			it('returns true if hashes match', function() {
				utils.sha1.returns(hash);

				expect(utils.checkPassword(hash, password)).to.be.true;
			});

			it('returns false if hashes do not match', function() {
				utils.sha1.returns('{SHA}other-hash');

				expect(utils.checkPassword(hash, password)).to.be.false;
			});
		});

		context('md5', function() {
			const hash = '$apr1$correct-hash';

			beforeEach(function() {
				sandbox.stub(utils, 'md5');
			});

			it('hashes salted password with ::md5', function() {
				utils.checkPassword(hash, password);

				expect(utils.md5).to.be.calledOnce;
				expect(utils.md5).to.be.calledOn(utils);
				expect(utils.md5).to.be.calledWith(password, hash);
			});

			it('returns true if hashes match', function() {
				utils.md5.returns(hash);

				expect(utils.checkPassword(hash, password)).to.be.true;
			});

			it('returns false if hashes do not match', function() {
				utils.md5.returns('$apr1$other-hash');

				expect(utils.checkPassword(hash, password)).to.be.false;
			});
		});

		context('crypt', function() {
			const hash = 'correct-hash';

			beforeEach(function() {
				sandbox.stub(utils, 'crypt');
			});

			it('hashes salted password with ::crypt', function() {
				utils.checkPassword(hash, password);

				expect(utils.crypt).to.be.calledOnce;
				expect(utils.crypt).to.be.calledOn(utils);
				expect(utils.crypt).to.be.calledWith(password, hash);
			});

			it('returns true if hashes match', function() {
				utils.crypt.returns('correct-hash');

				expect(utils.checkPassword(hash, password)).to.be.true;
			});

			it('returns false if hashes do not match', function() {
				utils.crypt.returns('other-hash');

				expect(utils.checkPassword(hash, password)).to.be.false;
			});
		});

		context('bcrypt', function() {
			const compareResult = 'compareSync result';

			beforeEach(function() {
				sandbox.stub(bcrypt, 'compareSync').returns(compareResult);
			});

			it('checks password with bcryptjs::compareSync', function() {
				let hash = '$2$correct-hash';

				let result = utils.checkPassword(hash, password);

				expect(bcrypt.compareSync).to.be.calledOnce;
				expect(bcrypt.compareSync).to.be.calledOn;
				expect(bcrypt.compareSync).to.be.calledWith(password, hash);
				expect(result).to.equal(compareResult);
			});

			it('supports alternate bcrypt prefixes', function() {
				let hash = '$2a$correct-hash';
				let other = '$2y$correct-hash';
				let otherCompareResult = 'other compareSync result';
				bcrypt.compareSync.onSecondCall().returns(otherCompareResult);

				let result = utils.checkPassword(hash, password);
				let otherResult = utils.checkPassword(other, password);

				expect(bcrypt.compareSync).to.be.calledTwice;
				expect(bcrypt.compareSync).to.always.be.calledOn(bcrypt);
				expect(bcrypt.compareSync).to.be.calledWith(password, hash);
				expect(bcrypt.compareSync).to.be.calledWith(password, other);
				expect(result).to.equal(compareResult);
				expect(otherResult).to.equal(otherCompareResult);
			});
		});
	});
});
