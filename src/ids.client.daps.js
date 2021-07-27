const
    {EventEmitter} = require('events'),
    //hrt   = require("core.hrtn"),
    fetch          = require("node-fetch"),
    vocab          = "#"
;

//region Error classes

class ErrorResponseNotOk extends Error {

    constructor(message, response) {
        super(message);
        Object.defineProperties(this, {
            'response': {value: response}
        });
    }
}

class ErrorSubjectIsMissing extends Error {
    constructor(message) {
        super(message);
    }
}

class ErrorDapsHostIsMissing extends Error {
    constructor(message) {
        super(message);
    }
}

//endregion Error classes

class DapsClient extends EventEmitter {

    #id                       = `dapsClient${vocab}`;
    #default_daps_host        = "";
    #default_daps_token_path  = "token";
    #default_daps_vc_path     = "vc";
    #default_token_context    = "https://w3id.org/idsa/contexts/context.jsonld";
    #default_token_expiration = 60; //REM one minute in seconds
    #subject                  = undefined; // REM: JWT.sub / JWT.iss, source = skiaki
    #default_scope            = "ids_connector_attributes"; //REM one minute in seconds

    constructor({
                    'daps_host':  daps_host = undefined,
                    'credential': credential = {
                        '@id':   "https://localhost/domain/credential#nrd_daps",
                        '@type': "domain:CredentialDapsAuthentication",
                        //'@type': "domain:BasicAtuhCredential",
                        'host': "https://daps.nicos-rd.com/token",
                        //'name': "https://gbx.nicos-rd.com",
                        'name': "sd:sdf:df:keyid:df:df:df" // REM: skiaki, used as JWT.sub and JWT.iss
                    },
                    //
                    'daps_token_path':  daps_token_path = undefined,
                    'daps_vc_path':     daps_vc_path = undefined,
                    'token_context':    token_context = undefined,
                    'token_expiration': token_expiration = undefined,
                    'subject':          subject = undefined,
                    'scope':            scope = undefined
                }
    ) {
        super();

        if (daps_host)
            this.#default_daps_host = daps_host;

        this.#default_daps_token_path  = (daps_token_path || this.#default_daps_token_path);
        this.#default_daps_vc_path     = (daps_vc_path || this.#default_daps_vc_path);
        this.#default_token_context    = (token_context || this.#default_token_context);
        this.#default_token_expiration = (token_expiration || this.#default_token_expiration);
        if (subject) // REM : source = skiaki
            this.#subject = subject;
        if (scope)
            this.#default_scope = (scope || this.#default_scope);

        Object.defineProperties(this['getDAT'], {
            '@id': {value: `${this.#id}getdat`}
        });
        Object.defineProperties(this['getVC'], {
            '@id': {value: `${this.#id}getvc`}
        });

    } // constructor

    get ['@id']() {
        return this.#id;
    }

    async getDAT({
                     'daps_host':       daps_host = undefined,
                     'daps_token_path': daps_token_path = undefined,
                     'context':         context = undefined,
                     'subject':         subject = undefined, // REM: JWT.sub AND JWT.iat, source = skiaki
                     'audience':        audience = undefined,
                     'expiration':      expiration = undefined,
                     'validNotBefore':  validNotBefore = undefined, // REM: JWT.nbf
                     'scope':           scope = undefined
                 }) {

        try {
            let
                // TODO: get from module 'time' OR 'core.hrt''
                iat   = Math.round(Date.now() / 1000), // REM: JWT.iat
                //iat = hrt()
                token = {
                    '@context': (context || this.#default_token_context),
                    '@type':    "ids:DatRequestToken",
                    'iat':      iat
                },
                client_assertion,
                body,
                DAT   = undefined
            ;

            daps_host = (daps_host || this.#default_daps_host);

            if ((!daps_host) || (daps_host === ""))
                //throw (new Error(`DapsClient.getDAT : 'daps_host' is missing.`));
                throw new ErrorDapsHostIsMissing(`DapsClient.getDAT : 'daps_host' is missing.`);

            daps_token_path = (daps_token_path || this.#default_daps_token_path);

            // REM: source = skiaki
            subject = (subject || this.#subject);
            if (!subject)
                //throw (new Error(`DapsClient.getDAT : 'subject' is missing.`));
                throw new ErrorSubjectIsMissing(`DapsClient.getDAT : 'subject' is missing.`);

            validNotBefore = (validNotBefore || iat);
            expiration     = (expiration || this.#default_token_expiration);

            token['iss'] = subject; // skiaki
            token['sub'] = subject; // skiaki
            if (audience)
                token['aud'] = audience;
            token['nbf'] = validNotBefore;
            token['exp'] = (iat + expiration);

            scope = (scope || this.#default_scope);

            // TODO: client_assertion
            client_assertion = 'asdf.asdf.asdf';

            body = `grant_type=client_credentials
            &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
            &client_assertion="${client_assertion}"
            &scope=${scope}`;

            let
                options = {
                    'method': "POST",
                    // TODO
                    'host':           daps_host,
                    'mode':           "cors",
                    'cache':          "no-cache",
                    'credentials':    "same-origin",
                    'headers':        {},
                    'redirect':       "follow",
                    'referrerPolicy': "same-origin",

                    // TODO
                    'Content-Type': "application/x-www-form-urlencoded",

                    'body': body
                }
            ; // let

            this['emit']("getDAT.before.fetch", {
                'daps_token_path': daps_token_path,
                'options':         options
            });
            const response = await fetch(daps_token_path, options);

            if (!response['ok']) {
                //throw new ErrorResponseNotOk(`DapsClient.getDAT : 'response.ok' is <false>.`);
                throw new ErrorResponseNotOk(`${this['getDAT']['@id']} : 'response.ok' is <false>.`, response);
            } // if ()

            DAT = await response.text();
            DAT = JSON.parse(DAT);
            this['emit']("getDAT.result", DAT);
            return DAT;
        } catch (jex) {
            this['emit']("getDAT.exception", jex);
            throw jex;
        } // try
    } // getDAT

    async getVC() {
        try {
            let VC = {}
            ;
            return VC;
        } catch (jex) {
            throw jex;
        } // try
    } // getVC()

} // class DapsClient

module.exports = DapsClient;
