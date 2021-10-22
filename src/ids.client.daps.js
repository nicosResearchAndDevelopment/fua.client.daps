const
    _util                   = require('@nrd/fua.core.util'),
    {KeyObject}             = require('crypto'),
    util                    = {
        ..._util,
        assert: _util.Assert('ids.client.daps'),
        // isSKI:            _util.StringValidator(/^(?:[0-9a-f]{2}(?::|$)){20}(?=$)/i),
        // isAKI:            _util.StringValidator(/^keyid:(?:[0-9a-f]{2}(?::|$)){20}(?=$)/i),
        // isSKIAKI:            _util.StringValidator(/^(?:[0-9a-f]{2}(?::|$)){20}(?=$):keyid:(?:[0-9a-f]{2}(?::|$)){20}(?=$)/i),
        isSKIAKI:         _util.StringValidator(/^(?:[0-9a-f]{2}:){20}keyid(?::[0-9a-f]{2}){20}$/i),
        isNonEmptyString: _util.StringValidator(/^\S+$/),
        isExpiration:     (value) => _util.isInteger(value) && value > 0,
        isPrivateKey:     (value) => (value instanceof KeyObject) && value.type === 'private',
        isRequestAgent:   (value) => _util.isObject(value) && _util.isFunction(value.addRequest) && _util.isFunction(value.createConnection)
    },
    EventEmitter            = require('events'),
    {URL, URLSearchParams}  = require('url'),
    https                   = require('https'),
    fetch                   = require('node-fetch'),
    {SignJWT}               = require('jose/jwt/sign'),
    {jwtVerify}             = require('jose/jwt/verify'),
    {decodeProtectedHeader} = require('jose/util/decode_protected_header'),
    {parseJwk}              = require('jose/jwk/parse');

//region >> TYPEDEF
/**
 * @typedef {{"@context": "https://w3id.org/idsa/contexts/context.jsonld", "@type": "DatRequestPayload", iss: string, sub: string, aud: string, exp: number, nbf: number, iat: number}} DatRequestPayload
 * @see https://github.com/International-Data-Spaces-Association/IDS-G/blob/main/Components/IdentityProvider/DAPS/README.md#request-token-that-is-handed-in-at-daps-side Request token that is handed in at DAPS side
 */ /**
 * @typedef {string} DatRequestToken
 */ /**
 * @typedef {string} DatRequestQuery
 * @see https://github.com/International-Data-Spaces-Association/IDS-G/blob/main/Components/IdentityProvider/DAPS/README.md#request-call-to-get-a-token Request call to get a token
 */ /**
 * @typedef {{"@context": "https://w3id.org/idsa/contexts/context.jsonld", "@type": "DatPayload", iss: string, sub: string, aud: string, exp: number, nbf: number, iat: number, scope: Array<string>, securityProfile: string, referringConnector?: string, transportCertsSha256?: string | Array<string>, extendedGuarantee?: string}} DatPayload
 * @see https://github.com/International-Data-Spaces-Association/IDS-G/blob/main/Components/IdentityProvider/DAPS/README.md#dynamic-attribute-token-content Dynamic Attribute Token Content
 */ /**
 * @typedef {string} DynamicAttributeToken
 */ /**
 * @typedef {{kty: string, use?: "sig" | "enc", key_ops?: Array<"sign" | "verify" | "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits">, alg?: string, kid?: string, x5u?: string, x5c?: Array<string>, x5t?: string, "x5t#S256"?: string, k?: string, n?: string, e?: string, d?: string, crv?: string, x?: string, y?: string, p?: string, q?: string, dp?: string, dq?: string, qi?: string}} JsonWebKey
 * @see https://datatracker.ietf.org/doc/html/rfc7517#section-4 JSON Web Key (JWK) Format
 */
/**
 * @typedef {{keys: Array<JsonWebKey>}} JsonWebKeySet
 * @see https://datatracker.ietf.org/doc/html/rfc7517#section-5 JWK Set Format
 */
    //endregion >> TYPEDEF

class DapsClient extends EventEmitter {

    #daps_url       = 'http://localhost:4567';
    #daps_httpAgent = null;

    #jwks         = null;
    #jwks_created = 0;
    #jwks_maxAge  = (24 * 60 * 60);                                  // REM : 24h (twenty-four hours)

    #datRequest            = '';
    #datRequest_privateKey = null;
    #datRequest_algorithm  = 'RS256';
    #datRequest_subject    = '';
    #datRequest_expiration = (5 * 60);                                // REM : 5min (five minutes)
    #datRequest_audience   = 'idsc:IDS_CONNECTORS_ALL';
    #datRequest_scope      = 'idsc:IDS_CONNECTOR_ATTRIBUTES_ALL';

    #dat             = '';
    #dat_issuedAt    = 0;
    #dat_minLifespan = 60;

    /**
     * @param {Object} param
     * @param {string} param.SKIAKI
     * @param {string} param.dapsUrl
     * @param {KeyObject} param.privateKey
     * @param {string} [param.algorithm]
     * @param {number} [param.expiration]
     * @param {{addRequest: Function, createConnection: Function}} [param.requestAgent]
     */
    constructor(param) {
        util.assert(util.isObject(param), 'DapsClient#constructor : expected param to be an object', TypeError);
        util.assert(util.isSKIAKI(param.SKIAKI), 'DapsClient#constructor : expected param.SKIAKI to be a SKI:AKI string combination', TypeError);
        util.assert(util.isString(param.dapsUrl), 'DapsClient#constructor : expected param.dapsUrl to be a string', TypeError);
        util.assert(util.isPrivateKey(param.privateKey), 'DapsClient#constructor : expected param.privateKey to be a private KeyObject', TypeError);
        util.assert(util.isNull(param.algorithm) || util.isNonEmptyString(param.algorithm),
            'DapsClient#constructor : expected param.algorithm to be a nonempty string', TypeError);
        util.assert(util.isNull(param.expiration) || util.isExpiration(param.expiration),
            'DapsClient#constructor : expected param.expiration to be an integer greater than 0', TypeError);
        util.assert(util.isNull(param.requestAgent) || util.isRequestAgent(param.requestAgent),
            'DapsClient#constructor : expected param.requestAgent to be a request agent', TypeError);

        super(); // REM : EventEmitter

        this.#daps_url              = param.dapsUrl;
        this.#datRequest_audience   = param.dapsUrl;
        this.#datRequest_subject    = param.SKIAKI;
        this.#datRequest_privateKey = param.privateKey;
        if (param.expiration) this.#datRequest_expiration = param.expiration;
        if (param.algorithm) this.#datRequest_algorithm = param.algorithm;
        if (param.requestAgent) this.#daps_httpAgent = param.requestAgent;

    } // DapsClient#constructor

    /**
     * @param {Object} [param]
     * @returns {Promise<JsonWebKeySet>}
     */
    async fetchJwks(param) {
        const
            requestUrl = new URL('/.well-known/jwks.json', this.#daps_url).toString(),
            response   = await fetch(requestUrl);

        util.assert(response.ok, 'DapsClient#fetchJwks : [' + response.status + '] ' + response.statusText);

        const
            jwks = await response.json();

        util.assert(util.isArray(jwks?.keys), 'DapsClient#fetchJwks : expected jwks to have a keys array');
        util.freezeAllProp(jwks, Infinity);
        this.#jwks         = jwks;
        this.#jwks_created = 1e-3 * Date.now();

        return jwks;
    } // DapsClient#fetchJWKS

    /**
     * @param {Object} [param]
     * @param {number} [param.maxAge]
     * @returns {Promise<JsonWebKeySet>}
     */
    async getJwks(param) {
        if (!this.#jwks) return await this.fetchJwks(param);

        util.assert(util.isNull(param?.maxAge) || util.isExpiration(param.maxAge),
            'DapsClient#getJwks : expected param.maxAge to be an integer greater than 0', TypeError);

        const
            age    = 1e-3 * Date.now() - this.#jwks_created,
            maxAge = param?.maxAge ?? this.#jwks_maxAge;

        return age <= maxAge && this.#jwks || await this.fetchJwks(param);
    } // DapsClient#getJwks

    /**
     * @param {Object} [param]
     * @param {number} [param.expiration]
     * @returns {Promise<DatRequestPayload>}
     */
    async createDatRequestPayload(param) {
        util.assert(util.isNull(param?.expiration) || util.isExpiration(param.expiration),
            'DapsClient#createDatRequestPayload : expected param.expiration to be an integer greater than 0', TypeError);

        const
            now     = Math.trunc(1e-3 * Date.now()),
            payload = {
                '@context': 'https://w3id.org/idsa/contexts/context.jsonld',
                '@type':    'DatRequestPayload', // 'ids:DatRequestToken'
                iss:        this.#datRequest_subject,
                sub:        this.#datRequest_subject,
                aud:        this.#daps_url,
                // TODO : DAPS-TEST : what will happen, if we put it to past?!?
                exp: now + (param?.expiration ?? this.#datRequest_expiration),
                // TODO : DAPS-TEST : what will happen, if we put it to future?!?
                nbf: now,
                iat: now
            };

        if (param?.tweak_dat) {
            payload.tweak_dat = tweak_dat;
        } // if ()

        return payload;
    } // DapsClient#createDatRequestPayload

    /**
     * @param {Object} [param]
     * @param {number} [param.expiration]
     * @param {string} [param.algorithm]
     * @returns {Promise<DatRequestToken>}
     */
    async createDatRequestToken(param) {
        util.assert(util.isNull(param?.algorithm) || util.isNonEmptyString(param.algorithm),
            'DapsClient#createDatRequestToken : expected param.algorithm to be a nonempty string', TypeError);

        const
            header          = {alg: param?.algorithm ?? this.#datRequest_algorithm},
            payload         = await this.createDatRequestPayload(param),
            datRequestToken = await new SignJWT(payload)
                .setProtectedHeader(header)
                .sign(this.#datRequest_privateKey);

        return datRequestToken;
    } // DapsClient#createDatRequestToken

    /**
     * @param {Object} [param]
     * @param {number} [param.expiration]
     * @param {string} [param.algorithm]
     * @param {DatRequestToken} [param.datRequestToken]
     * @returns {Promise<DatRequestQuery>}
     */
    async createDatRequestQuery(param) {
        util.assert(util.isNull(param?.datRequestToken) || util.isNonEmptyString(param.datRequestToken),
            'DapsClient#createDatRequestQuery : expected param.datRequestToken to be a nonempty string', TypeError);

        const
            datRequestToken = param?.datRequestToken ?? await this.createDatRequestToken(param),
            queryParams     = {
                grant_type:            'client_credentials',
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                client_assertion:      datRequestToken,
                scope:                 this.#datRequest_scope
            },
            requestQuery    = new URLSearchParams(queryParams).toString();

        return requestQuery;
    } // DapsClient#createDatRequestQuery

    /**
     * @param {Object} [param]
     * @param {number} [param.expiration]
     * @param {string} [param.algorithm]
     * @param {DatRequestToken} [param.datRequestToken]
     * @param {DatRequestQuery} [param.datRequestQuery]
     * @returns {Promise<{url: string, method: string, headers: {[key: string]: string}, body: DatRequestQuery}>}
     */
    async createDatRequest(param) {
        util.assert(util.isNull(param?.datRequestQuery) || util.isNonEmptyString(param.datRequestQuery),
            'DapsClient#createDatRequest : expected param.datRequestQuery to be a nonempty string', TypeError);

        const
            requestUrl = new URL('/token', this.#daps_url).toString(),
            request    = {
                url:     requestUrl,
                method:  'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'},
                body:    param?.datRequestQuery ?? await this.createDatRequestQuery(param)
            };

        // REM : previous versn <!> if (!this.#daps_httpAgent) request.agent = this.#daps_httpAgent;
        if (this.#daps_httpAgent) request.agent = this.#daps_httpAgent;

        return request;
    } // DapsClient#createDatRequest

    /**
     * @param {Object} [param]
     * @param {number} [param.expiration]
     * @param {string} [param.algorithm]
     * @param {DatRequestToken} [param.datRequestToken]
     * @param {DatRequestQuery} [param.datRequestQuery]
     * @returns {Promise<DynamicAttributeToken>}
     */
    async fetchDat(param) {
        const
            request  = await this.createDatRequest(param),
            response = await fetch(request.url, request);

        util.assert(response.ok, 'DapsClient#fetchDat : [' + response.status + '] ' + response.statusText);

        const
            //result                = await response.json(),
             xxx result     = await response.text(),
            DAT        = result.access_token,
            datPayload = await this.validateDat(DAT, param);

        util.assert(datPayload.iss === this.#daps_url, 'DapsClient#fetchDat : expected issuer of the dat to be the daps');
        util.assert(datPayload.sub === this.#datRequest_subject, 'DapsClient#fetchDat : expected subject of the dat to be the client');

        this.#dat          = DAT;
        this.#dat_issuedAt = datPayload.iss;

        return DAT;
    } // DapsClient#fetchDat

    /**
     * @param {Object} [param]
     * @param {number} [param.expiration]
     * @param {string} [param.algorithm]
     * @param {DatRequestToken} [param.datRequestToken]
     * @param {DatRequestQuery} [param.datRequestQuery]
     * @param {number} [param.minLifespan]
     * @returns {Promise<DynamicAttributeToken>}
     */
    async getDat(param) {
        if (!this.#dat) return await this.fetchDat(param);

        util.assert(util.isNull(param?.minLifespan) || util.isExpiration(param.minLifespan),
            'DapsClient#getDat : expected param.minLifespan to be an integer greater than 0', TypeError);

        const
            lifespan    = 1e-3 * Date.now() - this.#dat_issuedAt,
            minLifespan = param?.minLifespan ?? this.#dat_minLifespan;

        return lifespan >= minLifespan && this.#dat || await this.fetchDat(param);
    } // DapsClient#getDat

    /**
     * @param {DynamicAttributeToken} dynamicAttributeToken
     * @param {Object} [param]
     * @param {number} [param.maxAge]
     * @returns {Promise<DatPayload>}
     */
    async validateDat(dynamicAttributeToken, param) {
        util.assert(util.isNonEmptyString(dynamicAttributeToken), 'DapsClient#validateDat : expected dynamicAttributeToken to be a non empty string');

        const
            jwks   = await this.getJwks(param),
            header = decodeProtectedHeader(dynamicAttributeToken),
            jwk    = header.kid ? jwks.keys.find(entry => header.kid === entry.kid) : jwks.keys.length === 1 ? jwks.keys[0] : undefined;

        util.assert(jwk, 'DapsClient#validateDat : jwk could not be selected');

        const
            publicKey     = await parseJwk(jwk, header.alg),
            verifyOptions = {issuer: this.#daps_url},
            {payload}     = await jwtVerify(dynamicAttributeToken, publicKey, verifyOptions);

        return payload;
    } // DapsClient#validateDat

    /**
     * @param {object} [options]
     * @returns {DatHttpsAgent}
     * @see https://nodejs.org/api/https.html#https_new_agent_options HTTPS - new Agent
     * @see https://nodejs.org/api/http.html#http_new_agent_options HTTP - new Agent
     * @see https://nodejs.org/api/net.html#net_socket_connect_options_connectlistener NET - socket.connect
     * @see https://nodejs.org/api/tls.html#tls_tls_connect_options_callback TLS - tls.connect
     */
    createDatHttpsAgent(options) {
        return new DatHttpsAgent(options, this);
    } // DapsClient#createDatAgent

    // TODO createTlsAgent or something like that

} // DapsClient

module.exports = DapsClient;

class DatHttpsAgent extends https.Agent {

    #dapsClient = null;

    /**
     * @param {object} options
     * @param {DapsClient} dapsClient
     * @see https://nodejs.org/api/https.html#https_new_agent_options HTTPS - new Agent
     */
    constructor(options, dapsClient) {
        util.assert(dapsClient instanceof DapsClient, 'DatHttpsAgent#constructor : expected dapsClient to be a DapsClient');
        super(options);
        this.#dapsClient = dapsClient;
    } // DatHttpsAgent#constructor

    /**
     * @param {module:http.OutgoingMessage} req
     * @param {...any} args
     * @returns {Promise<void>}
     */
    async addRequest(req, ...args) {
        _delayRequestUntilSocket(req);
        try {
            const dat = await this.#dapsClient.getDat();
            req.setHeader('Authorization', `Bearer ${dat}`);
            super.addRequest(req, ...args);
        } catch (err) {
            req.destroy(err);
            req.emit('error', err);
        }
    } // DatHttpsAgent#addRequest

} // DatHttpsAgent

/**
 * @param {module:http.OutgoingMessage} request
 * @returns {module:http.OutgoingMessage}
 */
function _delayRequestUntilSocket(request) {
    const
        endFunction   = request.end,
        writeFunction = request.write,
        endArgs       = [],
        writeArgs     = [];

    request.end = function (...args) {
        if (request.socket) {
            endFunction.apply(request, args);
        } else if (!endArgs.length) {
            endArgs.push(args);
            request.once('socket', function () {
                if (!writeArgs.length) {
                    endFunction.apply(request, endArgs.shift());
                }
            });
        }
    };

    request.write = function (...args) {
        if (request.socket) {
            writeFunction.apply(request, args);
        } else if (writeArgs.length) {
            writeArgs.push(args);
        } else {
            writeArgs.push(args);
            request.once('socket', function () {
                while (writeArgs.length) {
                    writeFunction.apply(request, writeArgs.shift());
                }
                if (endArgs.length) {
                    endFunction.apply(request, endArgs.shift());
                }
            });
        }
    };

    return request;
} // _delayRequestUntilSocket
