const utils = require('../../lib/utils');
const crypto = require('crypto');

describe('utils', function() {
	describe('::sha1', function() {
		it('returns base64 sha1 digest of a password', function() {
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
			expect(result).to.equal(hash.digest.firstCall.returnValue);
		});
	});

	describe('::checkPassword', function() {
		context('sha1', function() {
			const password = 'password';
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
				utils.sha1.returns('correct-hash');

				expect(utils.checkPassword(hash, password)).to.be.true;
			});

			it('returns false if hashes do not match', function() {
				utils.sha1.returns('other-hash');

				expect(utils.checkPassword(hash, password)).to.be.false;
			});
		});
	});
});
