const
    {describe, test} = require('mocha'),
    expect           = require('expect'),
    path             = require('path'),
    https            = require('https'),
    fetch            = require('node-fetch'),
    jose             = require('jose'),
    DAPSClient       = require('../src/ids.client.daps.js'),
    clientConfig     = {
        connector: require(path.join(process.env.FUA_JS_APP, 'nrd-ca/resources/nrd-testbed/ec/ids/component/alice/connector/client.js')),
        tlsServer: require(path.join(process.env.FUA_JS_APP, 'nrd-ca/resources/nrd-testbed/ec/ids/component/alice/tls-server/server.js'))
    },
    clientParam      = {
        dapsUrl:       'https://nrd-daps.nicos-rd.com:8082',
        dapsTokenPath: '/auth/token',
        dapsJwksPath:  '/auth/jwks.json',
        // dapsUrl:       'https://nrd-daps.nicos-rd.com:8082/auth',
        // dapsTokenPath: '/token',
        // dapsJwksPath:  '/jwks.json',
        dapsVcPath:   '/vc',
        SKIAKI:       clientConfig.connector.meta.SKIAKI,
        privateKey:   clientConfig.connector.privateKey,
        requestAgent: new https.Agent({
            ca:   clientConfig.tlsServer.ca,
            key:  clientConfig.tlsServer.key,
            cert: clientConfig.tlsServer.cert
        })
    };

describe('ids.client.omejdn-daps', function () {

    this.timeout(10e3);

    let dapsClient;
    before('construct a daps client', function () {
        expect(typeof DAPSClient).toBe('function');
        dapsClient = new DAPSClient(clientParam);
        expect(dapsClient).toBeInstanceOf(DAPSClient);
    });

    describe('manual setup', function () {

        test('get oauth metadata', async function () {
            const response = await fetch(
                clientParam.dapsUrl + '/auth/.well-known/oauth-authorization-server',
                {agent: clientParam.requestAgent}
            );
            expect(response.ok).toBeTruthy();
            const metadata = await response.json();
            console.log(metadata);
        });

        test('get auth jwks', async function () {
            const response = await fetch(
                clientParam.dapsUrl + clientParam.dapsJwksPath,
                {agent: clientParam.requestAgent}
            );
            expect(response.ok).toBeTruthy();
            const jwks = await response.json();
            expect(Array.isArray(jwks?.keys)).toBeTruthy();
            expect(jwks.keys.length).toBeGreaterThan(0);
            console.log(jwks);
        });

        test('get auth token', async function () {
            const
                issuedAt               = Math.floor(1e-3 * Date.now()),
                datRequestTokenPayload = {
                    '@context': 'https://w3id.org/idsa/contexts/context.jsonld',
                    '@type':    'ids:DatRequestPayload',
                    // '@type': 'ids:DatRequestToken',
                    iss:     clientConfig.connector.meta.SKIAKI,
                    sub:     clientConfig.connector.meta.SKIAKI,
                    // aud:     clientParam.dapsUrl.replace(/:\d+\//, '/') + '/auth',
                    aud: 'idsc:IDS_CONNECTORS_ALL',
                    iat: issuedAt,
                    nbf: issuedAt - 60,
                    // nbf: issuedAt,
                    exp: issuedAt + 300
                    // exp: issuedAt + 60
                },
                datRequestToken        = await new jose.SignJWT(datRequestTokenPayload)
                    .setProtectedHeader({alg: 'RS256'})
                    .sign(clientConfig.connector.privateKey),
                datRequestBody         = {
                    grant_type:            'client_credentials',
                    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    client_assertion:      datRequestToken,
                    client_id:             clientConfig.connector.meta.SKIAKI,
                    scope:                 'idsc:IDS_CONNECTOR_ATTRIBUTES_ALL'
                    // scope:                 'ids_connector_attributes'
                },
                datRequest             = {
                    // url:    new URL(clientParam.dapsTokenPath, clientParam.dapsUrl).toString(),
                    url:    clientParam.dapsUrl + clientParam.dapsTokenPath,
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'},
                    // headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    // body: new URLSearchParams(datRequestBody).toString(),
                    body: new URLSearchParams(datRequestBody),
                    // body:  Object.entries(datRequestBody).map(entry => entry.join('=')).join('&'),
                    agent: clientParam.requestAgent
                },
                datResponse            = await fetch(datRequest.url, datRequest);

            console.log(JSON.stringify(datRequestTokenPayload, null, 2));
            console.log(`[${datRequest.method}] ${datRequest.url}`);
            console.log(Object.entries(datRequest.headers).map(entry => '  - ' + entry.join(': ')).join('\n'));
            console.log(datRequest.body.toString().split('&').join('\n&'));
            if (!datResponse.ok) console.error(`[${datResponse.status}] ${datResponse.statusText}`);

            expect(datResponse.ok).toBeTruthy();
            console.log(await datResponse.text());
        });

    });

    test('the daps client should be able to get the jwks', async function () {
        const jwks = await dapsClient.getJwks();
        expect(Array.isArray(jwks?.keys)).toBeTruthy();
        expect(jwks.keys.length).toBeGreaterThan(0);
    });

    test('the daps client should be able to get a dat', async function () {
        const datRequestQuery = await dapsClient.createDatRequestQuery();
        console.log(Object.fromEntries(new URLSearchParams(datRequestQuery)));
        const dat = await dapsClient.getDat({datRequestQuery});
        expect(typeof dat).toBe('string');
        console.log(dat);
    });

});
