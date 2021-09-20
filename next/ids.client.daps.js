const
    _util                  = require('@nrd/fua.core.util'),
    {KeyObject}            = require('crypto'),
    util                   = {
        ..._util,
        assert:       _util.Assert('ids.client.daps'),
        isSKI:        _util.StringValidator(/^(?:[0-9a-f]{2}(?::|$)){20}(?=$)/i),
        isAKI:        _util.StringValidator(/^keyid:(?:[0-9a-f]{2}(?::|$)){20}(?=$)/i),
        isAlgorithms: _util.StringValidator(/^\S+$/),
        isExpiration: (value) => _util.isInteger(value) && value > 0,
        isPrivateKey: (value) => (value instanceof KeyObject) && value.type === 'private'
    },
    EventEmitter           = require('events'),
    {URL, URLSearchParams} = require('url'),
    {SignJWT}              = require('jose/jwt/sign'),
    {decode}               = require('jose/util/base64url');

module.exports = class DAPSAgent extends EventEmitter {

    #daps_url    = 'http://localhost:4567';
    #private_key = null;

    #assertion_algorithm  = 'RS256';
    #assertion_subject    = '';
    #assertion_expiration = 300;
    #assertion_audience   = 'http://localhost:4567'; // 'idsc:IDS_CONNECTORS_ALL' | 'ALL'
    // #assertion_scope      = 'IDS_CONNECTOR_ATTRIBUTES_ALL'; // 'idsc:IDS_CONNECTOR_ATTRIBUTES_ALL'

    constructor(param) {
        util.assert(util.isObject(param), 'DAPSAgent#constructor : expected param to be an object', TypeError);
        util.assert(util.isSKI(param.SKI), 'DAPSAgent#constructor : expected param.SKI to be a string', TypeError);
        util.assert(util.isAKI(param.AKI), 'DAPSAgent#constructor : expected param.AKI to be a string', TypeError);
        util.assert(util.isString(param.dapsUrl), 'DAPSAgent#constructor : expected param.dapsUrl to be a string', TypeError);
        util.assert(util.isPrivateKey(param.key), 'DAPSAgent#constructor : expected param.key to be a private KeyObject', TypeError);
        util.assert(util.isNull(param.algorithm) || util.isAlgorithms(param.algorithm),
            'DAPSAgent#constructor : expected param.algorithm to be a nonempty string', TypeError);
        util.assert(util.isNull(param.expiration) || util.isExpiration(param.expiration),
            'DAPSAgent#constructor : expected param.expiration to be an integer greater than 0', TypeError);

        super();

        this.#daps_url          = param.dapsUrl;
        this.#assertion_subject = param.SKI + ':' + param.AKI;
        this.#private_key       = param.key;
        if (param.expiration) this. #assertion_expiration = param.expiration;
        if (param.algorithm) this. #assertion_algorithm = param.algorithm;
    } // DAPSAgent#constructor

    async createClientAssertion(param) {
        util.assert(util.isNull(param?.algorithm) || util.isAlgorithms(param.algorithm),
            'DAPSAgent#constructor : expected param.algorithm to be a nonempty string', TypeError);
        util.assert(util.isNull(param?.expiration) || util.isExpiration(param.expiration),
            'DAPSAgent#constructor : expected param.expiration to be an integer greater than 0', TypeError);
        const
            now     = 1e-3 * Date.now(),
            header  = {
                alg: param.algorithm ?? this.#assertion_algorithm
            },
            payload = {
                '@context': 'https://w3id.org/idsa/contexts/context.jsonld',
                '@type':    'DatRequestPayload',
                // '@type':    'ids:DatRequestToken',
                iss: this.#assertion_subject,
                sub: this.#assertion_subject,
                aud: this.#assertion_audience,
                exp: now + (param.expiration ?? this.#assertion_expiration),
                nbf: now,
                iat: now
            };
        return await new SignJWT(payload)
            .setProtectedHeader(header)
            .sign(this.#private_key);
    } // DAPSAgent#createClientAssertion

};
