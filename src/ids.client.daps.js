const
    hrt   = require("core.hrtn"),
    fetch = require("node-fetch")
;

class DapsClient {

    #default_daps_host        = "";
    #default_daps_token_path  = "/token";
    #default_daps_vc_path     = "/vc";
    #default_token_context    = "https://w3id.org/idsa/contexts/context.jsonld";
    #default_token_expiration = (60 * 1); //REM one minute in seconds
    #subject                  = undefined; // REM: JWT.sub / JWT.iss, source = skiaki
    #default_scope            = "ids_connector_attributes"; //REM one minute in seconds

    constructor({
                    'daps_host':  daps_host = undefined,
                    'credential': credential = {
                        '@id': "https://localhost/domain/credential#nrd_daps",
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
        if (daps_host)
            this.#default_daps_host = daps_host;
        if (daps_token_path)
            this.#daps_token_path = daps_token_path;
        if (daps_vc_path)
            this.#daps_vc_path = daps_vc_path;
        if (token_context)
            this.#default_token_context = token_context;
        if (token_expiration)
            this.#default_token_expiration = token_expiration;
        if (subject) // REM : source = skiaki
            this.#subject = subject;
        if (scope)
            this.#default_scope = scope;
    } // constructor

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
                throw (new Error(`DapsClient.getDAT : 'daps_host' is missing.`));

            daps_token_path = (daps_token_path || this.#default_daps_token_path);

            // REM: source = skiaki
            subject = (subject || this.#subject);
            if (!subject)
                throw (new Error(`DapsClient.getDAT : 'subject' is missing.`));

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
                };

            const response = await fetch(daps_token_path, options);

            if (!response.ok)
                throw new Error(`DapsClient.getDAT : 'response.ok' is <false>.`);

            DAT = await response.text();
            DAT = JSON.parse(DAT);
            return DAT;
        } catch (jex) {
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
