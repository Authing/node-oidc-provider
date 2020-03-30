const {
  pickBy,
  isUndefined,
} = require('lodash');

const { assertPayload } = require('../../helpers/jwt');
const epochTime = require('../../helpers/epoch_time');
const instance = require('../../helpers/weak_cache');
const nanoid = require('../../helpers/nanoid');
// 根据每个 oidc client 的 metadata 动态生成 id_token issuer
function generateClientIssuer(providerIssuer, clientDomain) {
  let exp = /(https?:\/\/)([^.]*)/
  let [_, httpOrHttps] = exp.exec(providerIssuer)
  let host = providerIssuer.replace(exp, clientDomain)
  return httpOrHttps + host
}
module.exports = provider => ({
  // For tokens having their surface reduced by authentication we aim for the recommended 160 bits,
  // bearer tokens we aim for 256 bits.
  //
  // Default nanoid has a (26+26+10+2 = 64) symbol alphabet (6 bits). So with 6 bits per symbol, and
  // 27 symbols, we arrive at (6*27 = 162) total bits while for Bearer we go for 43 symbols
  // (6*27 = 258) total bits.

  // >= 256 bits
  //   RegistrationAccessToken
  //   ClientCredentials
  //   InitialAccessToken
  //   AccessToken
  // >= 160 bits
  //   RefreshToken
  //   AuthorizationCode
  //   DeviceCode
  generateTokenId() {
    switch (this.constructor.name) {
      case 'DeviceCode':
      case 'RefreshToken':
      case 'AuthorizationCode':
        return nanoid(27);
      default:
        return nanoid(43);
    }
  },
  async getValueAndPayload() {
    const now = epochTime();
    const exp = this.exp || now + this.expiration;
    const value = this.jti;
    let client = await provider.Client.find(this.clientId);

    const payload = {
      iat: this.iat || epochTime(),
      iss: generateClientIssuer(provider.issuer, client.domain),
      ...(exp ? { exp } : undefined),
      ...pickBy(
        this,
        (val, key) => this.constructor.IN_PAYLOAD.includes(key) && !isUndefined(val),
      ),
    };

    return [value, payload];
  },
  getTokenId(token) {
    return token;
  },
  async verify(token, stored, { ignoreExpiration, foundByUserCode }) {
    let client = await provider.Client.find(stored.clientId);
    assertPayload(stored, {
      ignoreExpiration,
      issuer: generateClientIssuer(provider.issuer, client.domain),
      clockTolerance: instance(provider).configuration('clockTolerance'),
      ...(foundByUserCode ? undefined : { jti: token }),
    });

    return stored;
  },
});
