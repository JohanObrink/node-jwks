import debug from 'debug';
import axios from 'axios';
import JwksError from './errors/JwksError';
import { certToPEM, rsaPublicKeyToPEM } from './utils';

const logger = debug('jwks');

function parseKey(key) {
  if (key.x5c && key.x5c.length) {
    return { kid: key.kid, nbf: key.nbf, publicKey: certToPEM(key.x5c[0]) };
  } else {
    return { kid: key.kid, nbf: key.nbf, rsaPublicKey: rsaPublicKeyToPEM(key.n, key.e) };
  }
}

export default async function getKey(jwksUri, cb) {
  logger(`Fetching keys from '${jwksUri}'`);
  try {
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };
    const { data } = await axios.get(jwksUri, { headers });
    const key = parseKey(data);
    if (typeof cb === 'function') {
      cb(null, key);
    } else {
      return key;
    }
  } catch (err) {
    if (err.response) {
      const message = (err.response.data || `Http Error ${err.response.statusCode}`)
        || err.message;
      err = new JwksError(message);
    }
    if (typeof cb === 'function') {
      cb(err);
    } else {
      throw err;
    }
  }
}
