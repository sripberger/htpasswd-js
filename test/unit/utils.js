const utils = require('../../lib/utils');
const bcrypt = require('bcryptjs');
const hashUtils = require('../../lib/hash-utils');

describe('utils', function() {
	describe('::checkPassword', function() {
		const password = 'password';

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

		context('md5', function() {
			const hash = '$apr1$correct-hash';

			beforeEach(function() {
				sandbox.stub(hashUtils, 'md5');
			});

			it('hashes salted password with hashUtils::md5', function() {
				utils.checkPassword(hash, password);

				expect(hashUtils.md5).to.be.calledOnce;
				expect(hashUtils.md5).to.be.calledOn(hashUtils);
				expect(hashUtils.md5).to.be.calledWith(password, hash);
			});

			it('returns true if hashes match', function() {
				hashUtils.md5.returns(hash);

				expect(utils.checkPassword(hash, password)).to.be.true;
			});

			it('returns false if hashes do not match', function() {
				hashUtils.md5.returns('$apr1$other-hash');

				expect(utils.checkPassword(hash, password)).to.be.false;
			});
		});

		context('sha1', function() {
			const hash = '{SHA}correct-hash';

			beforeEach(function() {
				sandbox.stub(hashUtils, 'sha1');
			});

			it('hashes password with hashUtils::sha1', function() {
				utils.checkPassword(hash, password);

				expect(hashUtils.sha1).to.be.calledOnce;
				expect(hashUtils.sha1).to.be.calledOn(hashUtils);
				expect(hashUtils.sha1).to.be.calledWith(password);
			});

			it('returns true if hashes match', function() {
				hashUtils.sha1.returns(hash);

				expect(utils.checkPassword(hash, password)).to.be.true;
			});

			it('returns false if hashes do not match', function() {
				hashUtils.sha1.returns('{SHA}other-hash');

				expect(utils.checkPassword(hash, password)).to.be.false;
			});
		});

		context('crypt', function() {
			const hash = 'correct-hash';

			beforeEach(function() {
				sandbox.stub(hashUtils, 'crypt');
			});

			it('hashes salted password with hashUtils::crypt', function() {
				utils.checkPassword(hash, password);

				expect(hashUtils.crypt).to.be.calledOnce;
				expect(hashUtils.crypt).to.be.calledOn(hashUtils);
				expect(hashUtils.crypt).to.be.calledWith(password, hash);
			});

			it('returns true if hashes match', function() {
				hashUtils.crypt.returns('correct-hash');

				expect(utils.checkPassword(hash, password)).to.be.true;
			});

			it('returns false if hashes do not match', function() {
				hashUtils.crypt.returns('other-hash');

				expect(utils.checkPassword(hash, password)).to.be.false;
			});
		});
	});
});
