const assert = require('assert');

const base64url = require('base64url');

const JWT = require('../../helpers/jwt');
const instance = require('../../helpers/weak_cache');
const nanoid = require('../../helpers/nanoid');

const opaqueFormat = require('./opaque');

function getClaim(token, claim) {
  return JSON.parse(base64url.decode(token.split('.')[1]))[claim];
}

const use = 'sig';
const FALLBACK_ALG = 'RS256';

module.exports = (provider) => {
  const opaque = opaqueFormat(provider);

  async function getSigningAlgAndKey(clientId) {
    let alg = FALLBACK_ALG;
    let client;
    if (clientId) {
      client = await provider.Client.find(clientId);
      assert(client);
      if (client.idTokenSignedResponseAlg !== 'none') {
        alg = client.idTokenSignedResponseAlg;
      }
    }

    // 修复 access token 签名问题，使用用户自定义的签名密钥
    let keystore = client.keystore;
    let key = keystore && keystore.get({ alg, use });
    if(!key) {
      // 如果用户没有自定义 RSA 加密秘钥，就使用 OIDC Provider 默认的
      keystore = instance(provider).keystore;
      key = keystore && keystore.get({ alg, use });
    }

    return { key, alg };
  }

  return {
    generateTokenId() {
      return nanoid();
    },
    async getValueAndPayload() {
      const [, payload] = await opaque.getValueAndPayload.call(this);
      const {
        jti, accountId: sub, iss, iat, exp, scope, aud, clientId: azp, 'x5t#S256': S256,
      } = payload;

      let value;
      if (this.jwt) {
        value = this.jwt;
      } else {
        const { key, alg } = await getSigningAlgAndKey(azp);
        value = await JWT.sign({
          jti,
          sub,
          iss,
          iat,
          exp,
          scope,
          ...(S256 ? { cnf: { 'x5t#S256': S256 } } : undefined),
          ...(aud ? { aud, azp } : { aud: azp }),
        }, key, alg);
      }
      payload.jwt = value;

      return [value, payload];
    },
    getTokenId(token) {
      return getClaim(token, 'jti');
    },
    async verify(token, stored, { ignoreExpiration, foundByUserCode }) {
      let jti;
      if (!foundByUserCode) {
        assert.deepEqual(token, stored.jwt);
        jti = this.getTokenId(token);
      }
      return opaque.verify.call(this, jti, stored, { ignoreExpiration, foundByUserCode });
    },
  };
};
