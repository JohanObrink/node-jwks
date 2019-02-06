import nock from 'nock';
import { expect } from 'chai';
import { x5cSingle } from './keys';
import getKey from '../src/getKey';

describe('#getKey', () => {
  const jwksHost = 'http://my-authz-server';

  beforeEach(() => {
    nock.cleanAll();
  });

  it('should handle errors', (done) => {
    nock(jwksHost)
      .get('/.well-known/jwks/key-id')
      .reply(500, 'Unknown Server Error');

    getKey(`${jwksHost}/.well-known/jwks/key-id`, (err) => {
      try {
        expect(err).not.to.be.null;
        expect(err.message).to.equal('Unknown Server Error');
        done();
      } catch (err) {
        done(err);
      }
    });
  });

  it('should return a publicKey', (done) => {
    nock(jwksHost)
      .get('/.well-known/jwks/NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA')
      .reply(200, x5cSingle.keys[0]);

    getKey(`${jwksHost}/.well-known/jwks/NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA`, (err, key) => {
      try {
        expect(err).to.be.null;
        expect(key.publicKey).to.match(/-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g);
        expect(key.kid).to.equal('NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA');
        done();
      } catch (err) {
        done(err);
      }
    });
  });
  it('(async) should return a publicKey', async () => {
    nock(jwksHost)
      .get('/.well-known/jwks/NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA')
      .reply(200, x5cSingle.keys[0]);

    try {
      const key = await getKey(`${jwksHost}/.well-known/jwks/NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA`);
      expect(key.publicKey).to.match(/-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g);
      expect(key.kid).to.equal('NkFCNEE1NDFDNTQ5RTQ5OTE1QzRBMjYyMzY0NEJCQTJBMjJBQkZCMA');
    } catch (err) {
      expect(err).to.be.null;
    }
  });
});
