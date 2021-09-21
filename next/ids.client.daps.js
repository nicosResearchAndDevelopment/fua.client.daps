const
    _util                  = require('@nrd/fua.core.util'),
    {KeyObject}            = require('crypto'),
    util                   = {
        ..._util,
        assert:           _util.Assert('ids.client.daps'),
        isSKI:            _util.StringValidator(/^(?:[0-9a-f]{2}(?::|$)){20}(?=$)/i),
        isAKI:            _util.StringValidator(/^keyid:(?:[0-9a-f]{2}(?::|$)){20}(?=$)/i),
        isNonEmptyString: _util.StringValidator(/^\S+$/),
        isExpiration:     (value) => _util.isInteger(value) && value > 0,
        isPrivateKey:     (value) => (value instanceof KeyObject) && value.type === 'private',
        isRequestAgent:   (value) => _util.isObject(value) && _util.isFunction(value.addRequest) && _util.isFunction(value.createConnection)
    },
    EventEmitter           = require('events'),
    {URL, URLSearchParams} = require('url'),
    fetch                  = require('node-fetch'),
    {SignJWT}              = require('jose/jwt/sign'),
    {decode}               = require('jose/util/base64url');

//region >> TYPEDEF
/**
 * @typedef {{"@context": "https://w3id.org/idsa/contexts/context.jsonld", "@type": "DatRequestPayload", iss: string, sub: string, aud: string, exp: number, nbf: number, iat: number}} DatRequestPayload
 */ /**
 * @typedef {string} DatRequestToken
 */ /**
 * @typedef {string} DatRequestQuery
 */ /**
 * @typedef {{"@context": "https://w3id.org/idsa/contexts/context.jsonld", "@type": "DatPayload", iss: string, sub: string, aud: string, exp: number, nbf: number, iat: number, scope: string | Array<string>, securityProfile: string, referringConnector?: string, transportCertsSha256?: string | Array<string>, extendedGuarantee?: string}} DatPayload
 */ /**
 * @typedef {string} DynamicAttributeToken
 */
//endregion >> TYPEDEF

module.exports = class DAPSAgent extends EventEmitter {

    #daps_url      = 'http://localhost:4567';
    #request_agent = null;
    #private_key   = null;

    #assertion_algorithm  = 'RS256';
    #assertion_subject    = '';
    #assertion_expiration = 300;
    #assertion_audience   = 'http://localhost:4567'; // 'idsc:IDS_CONNECTORS_ALL' | 'ALL'
    #assertion_scope      = 'IDS_CONNECTOR_ATTRIBUTES_ALL'; // 'idsc:IDS_CONNECTOR_ATTRIBUTES_ALL'

    /**
     * @param {Object} param
     * @param {string} param.SKI
     * @param {string} param.AKI
     * @param {string} param.dapsUrl
     * @param {KeyObject} param.privateKey
     * @param {string} [param.algorithm]
     * @param {number} [param.expiration]
     * @param {{addRequest: Function, createConnection: Function}} [param.requestAgent]
     */
    constructor(param) {
        util.assert(util.isObject(param), 'DAPSAgent#constructor : expected param to be an object', TypeError);
        util.assert(util.isSKI(param.SKI), 'DAPSAgent#constructor : expected param.SKI to be a string', TypeError);
        util.assert(util.isAKI(param.AKI), 'DAPSAgent#constructor : expected param.AKI to be a string', TypeError);
        util.assert(util.isString(param.dapsUrl), 'DAPSAgent#constructor : expected param.dapsUrl to be a string', TypeError);
        util.assert(util.isPrivateKey(param.privateKey), 'DAPSAgent#constructor : expected param.privateKey to be a private KeyObject', TypeError);
        util.assert(util.isNull(param.algorithm) || util.isNonEmptyString(param.algorithm),
            'DAPSAgent#constructor : expected param.algorithm to be a nonempty string', TypeError);
        util.assert(util.isNull(param.expiration) || util.isExpiration(param.expiration),
            'DAPSAgent#constructor : expected param.expiration to be an integer greater than 0', TypeError);
        util.assert(util.isNull(param.requestAgent) || util.isRequestAgent(param.requestAgent),
            'DAPSAgent#constructor : expected param.requestAgent to be a request agent', TypeError);

        super();

        this.#daps_url          = param.dapsUrl;
        this.#assertion_subject = param.SKI + ':' + param.AKI;
        this.#private_key       = param.privateKey;
        if (param.expiration) this.#assertion_expiration = param.expiration;
        if (param.algorithm) this.#assertion_algorithm = param.algorithm;
        if (param.requestAgent) this.#request_agent = param.requestAgent;
    } // DAPSAgent#constructor

    // * @returns {{"@context": "https://w3id.org/idsa/contexts/context.jsonld", "@type": "DatRequestPayload", iss: string, sub: string, aud: string, exp: number, nbf: number, iat: number}}

    /**
     * @param {Object} [param]
     * @param {number} [param.expiration]
     * @returns {Promise<DatRequestPayload>}
     */
    async createDatRequestPayload(param) {
        util.assert(util.isNull(param?.expiration) || util.isExpiration(param.expiration),
            'DAPSAgent#createDatRequestPayload : expected param.expiration to be an integer greater than 0', TypeError);

        const
            now     = 1e-3 * Date.now(),
            payload = {
                '@context': 'https://w3id.org/idsa/contexts/context.jsonld',
                '@type':    'DatRequestPayload', // 'ids:DatRequestToken'
                iss:        this.#assertion_subject,
                sub:        this.#assertion_subject,
                aud:        this.#assertion_audience,
                exp:        now + (param?.expiration ?? this.#assertion_expiration),
                nbf:        now,
                iat:        now
            };

        return payload;
    } // DAPSAgent#createDatRequestPayload

    /**
     * @param {Object} [param]
     * @param {number} [param.expiration]
     * @param {string} [param.algorithm]
     * @returns {Promise<DatRequestToken>}
     */
    async createDatRequestToken(param) {
        util.assert(util.isNull(param?.algorithm) || util.isNonEmptyString(param.algorithm),
            'DAPSAgent#createDatRequestToken : expected param.algorithm to be a nonempty string', TypeError);

        const
            header          = {alg: param?.algorithm ?? this.#assertion_algorithm},
            payload         = await this.createDatRequestPayload(param),
            datRequestToken = await new SignJWT(payload)
                .setProtectedHeader(header)
                .sign(this.#private_key);

        return datRequestToken;
    } // DAPSAgent#createDatRequestToken

    /**
     * @param {Object} [param]
     * @param {number} [param.expiration]
     * @param {string} [param.algorithm]
     * @param {DatRequestToken} [param.datRequestToken]
     * @returns {Promise<DatRequestQuery>}
     */
    async createDatRequestQuery(param) {
        util.assert(util.isNull(param?.datRequestToken) || util.isNonEmptyString(param.datRequestToken),
            'DAPSAgent#createDatRequestQuery : expected param.datRequestToken to be a nonempty string', TypeError);

        const
            datRequestToken = param?.datRequestToken ?? await this.createDatRequestToken(param),
            queryParams     = {
                grant_type:            'client_credentials',
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                client_assertion:      datRequestToken,
                scope:                 this.#assertion_scope
            },
            requestQuery    = new URLSearchParams(queryParams).toString();

        return requestQuery;
    } // DAPSAgent#createDatRequestQuery

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
            'DAPSAgent#createDatRequest : expected param.datRequestQuery to be a nonempty string', TypeError);

        const
            requestUrl = new URL('/token', this.#daps_url).toString(),
            request    = {
                url:     requestUrl,
                method:  'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'},
                body:    param?.datRequestQuery ?? await this.createDatRequestQuery(param)
            };

        if (!this.#request_agent) request.agent = this.#request_agent;

        return request;
    } // DAPSAgent#createDatRequest

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

        util.assert(response.ok, 'DAPSAgent#fetchDat : [' + response.status + '] ' + response.statusText);

        const
            result                = await response.json(),
            dynamicAttributeToken = result.access_token;

        util.assert(util.isNonEmptyString(dynamicAttributeToken), 'DAPSAgent#fetchDat : expected dynamicAttributeToken to be a non empty string');

        return dynamicAttributeToken;
    } // DAPSAgent#fetchDat

    async fetchJwks(param) {
        const
            requestUrl = new URL('/.well-known/jwks.json', this.#daps_url).toString(),
            response   = await fetch(requestUrl);

        util.assert(response.ok, 'DAPSAgent#fetchJwks : [' + response.status + '] ' + response.statusText);

        const
            jwks = await response.json();

        util.assert(util.isArray(jwks?.keys), 'DAPSAgent#fetchJwks : expected jwks to have a keys array');

        return jwks;
    } // DAPSAgent#fetchJWKS

    /**
     * @param {DynamicAttributeToken} dynamicAttributeToken
     * @returns {Promise<DatPayload>}
     */
    async validateDat(dynamicAttributeToken) {
        util.assert(util.isNonEmptyString(dynamicAttributeToken), 'DAPSAgent#validateDat : expected dynamicAttributeToken to be a non empty string');
        // TODO
    } // DAPSAgent#validateDat

};
