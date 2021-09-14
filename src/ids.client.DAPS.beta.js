const

    {SignJWT} = require('jose/jwt/sign')
;

class ErrorClientDapsIdIsMissing extends Error {
    constructor(message) {
        super(`[${timestamp()}] : ids.client.daps : ClientDaps :: ${message}`);
    }
}

function ClientDaps({
                        'id':                   id = undefined,
                        'daps_host':            daps_host_default = undefined,
                        'skiaki':               skiaki,
                        'jwt_header_algorithm': jwt_header_algorithm_default = "RS256",
                        'private_key':          private_key,
                        'jwt_aud':              jwt_aud_default, // TODO
                        'jwt_exp_offset':       jwt_exp_offset_default = 60, // REM in seconds
                        'scope':                scope_default = undefined
                    }) {

    let
        clientDaps = {}
    ;

    if (new.target) {

        if (!id)
            throw new ErrorClientDapsIdIsMissing("id is missing");

        Object.defineProperties(clientDaps, {
            'id':                     {
                value:      id,
                enumerable: true
            },
            'produceDatRequestToken': {
                value:         async ({
                                          //'daps_host': daps_host = undefined,
                                          //'daps_token_path': daps_token_path = undefined,
                                          //'context':         context = undefined,
                                          //'subject':         subject = undefined, // REM: JWT.sub AND JWT.iat, source = skiaki
                                          //'audience':        audience = undefined,
                                          //'expiration':      expiration = undefined,
                                          //'validNotBefore':  validNotBefore = undefined, // REM: JWT.nbf
                                          'jwt_header_algorithm': jwt_header_algorithm,
                                          'jwt_aud':              jwt_aud, // TODO
                                          'jwt_exp_offset':       jwt_exp_offset, // REM in seconds
                                          'scope':                scope = undefined
                                          ,
                                          'format': format = "string"
                                      }) => {

                    let
                        iat             = Math.round((new Date).valueOf() / 1000), // REM : seconds
                        //iat = hrt({'mode': "floor"}),
                        jwt_header      = {
                            //'type':       this.#jwt_header_type,
                            'alg': (jwt_header_algorithm || jwt_header_algorithm_default) // TODO: welcher ALGO?!
                        },
                        jwt_payload     = {
                            '@context': "https://w3id.org/idsa/contexts/context.jsonld",
                            '@type':    "ids:DatRequestToken"
                            ,
                            'aud': (jwt_aud || jwt_aud_default)
                            ,
                            'iss': skiaki,
                            'sub': skiaki,
                            'exp': Math.round(iat + (jwt_exp_offset || jwt_exp_offset_default)), // REM: seconds
                            'iat': iat, // REM: seconds
                            'nbf': iat  // REM: seconds
                        },
                        datRequestToken = {
                            'grant_type':            "client_credentials",
                            'client_assertion_type': "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            'client_assertion':      undefined,
                            'scope':                 undefined
                        }
                    ;

                    datRequestToken.scope = (scope || scope_default);

                    datRequestToken.client_assertion = await new SignJWT(jwt_payload)
                        .setProtectedHeader(jwt_header)
                        .sign(private_key);

                    switch (format) {
                        case "json":
                            break;
                        case "string":
                            datRequestToken = `grant_type=${datRequestToken.grant_type}&client_assertion_type=${datRequestToken.client_assertion_type}&client_assertion=${datRequestToken.client_assertion}&scope=${datRequestToken.scope}`;
                            break;
                        default:
                            throw new Error(`ids.client.daps : produceDatRequestToken : unknown format <${format}>`);
                            break;
                    } // switch(format)

                    return datRequestToken;

                }, enumerable: false
            }, // produceDatRequestToken
            'getDAT':                 {
                value:         async ({
                                          'daps_host': daps_host = undefined
                                          //'daps_token_path': daps_token_path = undefined,
                                          //'context':         context = undefined,
                                          //'subject':         subject = undefined, // REM: JWT.sub AND JWT.iat, source = skiaki
                                          //'audience':        audience = undefined,
                                          //'expiration':      expiration = undefined,
                                          //'validNotBefore':  validNotBefore = undefined, // REM: JWT.nbf
                                          //'scope':           scope = undefined
                                      }) => {

                    try {

                        let
                            requestToken = await clientDaps.produceRequestToken({
                                'daps_host': daps_host
                                //'format': "string"
                            }),

                            daps_host    = (daps_host || daps_host_default);

                        return undefined;
                    } catch (jex) {
                        this['emit']("getDAT.exception", jex);
                        throw jex;
                    } // try

                }, enumerable: false
            } // getDAT
            //'getDAT': {
            //    value:         async ({
            //                              'daps_host':       daps_host = undefined,
            //                              'daps_token_path': daps_token_path = undefined,
            //                              'context':         context = undefined,
            //                              'subject':         subject = undefined, // REM: JWT.sub AND JWT.iat, source = skiaki
            //                              'audience':        audience = undefined,
            //                              'expiration':      expiration = undefined,
            //                              'validNotBefore':  validNotBefore = undefined, // REM: JWT.nbf
            //                              'scope':           scope = undefined
            //                          }) => {
            //
            //        try {
            //
            //            let
            //                // TODO: get from module 'time' OR 'core.hrt''
            //                iat   = Math.round(Date.now() / 1000), // REM: JWT.iat
            //                //iat = hrt()
            //                token = {
            //                    '@context': (context || this.#default_token_context),
            //                    '@type':    "ids:DatRequestToken",
            //                    'iat':      iat
            //                },
            //                client_assertion,
            //                body,
            //                DAT   = undefined
            //            ;
            //
            //            daps_host = (daps_host || this.#default_daps_host);
            //
            //            if ((!daps_host) || (daps_host === ""))
            //                //throw (new Error(`DapsClient.getDAT : 'daps_host' is missing.`));
            //                throw new ErrorDapsHostIsMissing(`DapsClient.getDAT : 'daps_host' is missing.`);
            //
            //            daps_token_path = (daps_token_path || this.#default_daps_token_path);
            //
            //            // REM: source = skiaki
            //            subject = (subject || this.#subject);
            //            if (!subject)
            //                //throw (new Error(`DapsClient.getDAT : 'subject' is missing.`));
            //                throw new ErrorSubjectIsMissing(`DapsClient.getDAT : 'subject' is missing.`);
            //
            //            validNotBefore = (validNotBefore || iat);
            //            expiration     = (expiration || this.#default_token_expiration);
            //
            //            token['iss'] = subject; // skiaki
            //            token['sub'] = subject; // skiaki
            //            if (audience)
            //                token['aud'] = audience;
            //            token['nbf'] = validNotBefore;
            //            token['exp'] = (iat + expiration);
            //
            //            scope = (scope || this.#default_scope);
            //
            //            // TODO: client_assertion
            //            client_assertion = 'asdf.asdf.asdf';
            //
            //            body = `grant_type=client_credentials
            //    &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
            //    &client_assertion="${client_assertion}"
            //    &scope=${scope}`;
            //
            //            let
            //                options = {
            //                    'method': "POST",
            //                    // TODO
            //                    'host':           daps_host,
            //                    'mode':           "cors",
            //                    'cache':          "no-cache",
            //                    'credentials':    "same-origin",
            //                    'headers':        {},
            //                    'redirect':       "follow",
            //                    'referrerPolicy': "same-origin",
            //
            //                    // TODO
            //                    'Content-Type': "application/x-www-form-urlencoded",
            //
            //                    'body': body
            //                }
            //            ; // let
            //
            //            this['emit']("getDAT.before.fetch", {
            //                'daps_token_path': daps_token_path,
            //                'options':         options
            //            });
            //            const response = await fetch(daps_token_path, options);
            //
            //            if (!response['ok']) {
            //                //throw new ErrorResponseNotOk(`DapsClient.getDAT : 'response.ok' is <false>.`);
            //                throw new ErrorResponseNotOk(`${this['getDAT']['@id']} : 'response.ok' is <false>.`, response);
            //            } // if ()
            //
            //            DAT = await response.text();
            //            DAT = JSON.parse(DAT);
            //            this['emit']("getDAT.result", DAT);
            //            return DAT;
            //        } catch (jex) {
            //            this['emit']("getDAT.exception", jex);
            //            throw jex;
            //        } // try
            //    }, enumerable: false
            //} // getDAT
        }); // Object.defineProperties()
    } // if ()

    Object.freeze(clientDaps);

    return clientDaps;

} // ClientDaps ()

Object.defineProperties(ClientDaps, {
    'id': {value: "http://www.nicos-rd.com/fua/ids#ClientDaps", enumerable: true}
});

exports.ClientDaps = ClientDaps;