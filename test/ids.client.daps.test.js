const
    {describe, test} = require('mocha'),
    expect           = require('expect'),
    https            = require('https'),
    DAPSClient       = require('../src/ids.client.daps.js'),
    _client          = require('./certs/client.js');

// REM: node .\app\nrd-testbed\ec\ids\src\scripts\setup.omejdn-daps.js add-client --load .\lib\ids\ids.client.daps\test\certs\client.js

describe('ids.client.daps', function () {

    this.timeout(10e3);

    let dapsClient;
    before('construct a daps client', function () {
        expect(typeof DAPSClient).toBe('function');
        dapsClient = new DAPSClient({
            dapsUrl:    'http://localhost:4567',
            SKIAKI:     _client.meta.SKIAKI,
            privateKey: _client.privateKey
        });
        expect(dapsClient).toBeInstanceOf(DAPSClient);
        console.log(dapsClient);
    });

    // test('the daps client should be able to fetch a new dat', async function () {
    //     const dat = await dapsClient.fetchDat();
    //     expect(typeof dat).toBe('string');
    //     console.log(dat);
    // });
    //
    // test('the daps client should be able to fetch the jwks', async function () {
    //     const jwks = await dapsClient.fetchJwks();
    //     expect(Array.isArray(jwks?.keys)).toBeTruthy();
    //     console.log(jwks);
    // });
    //
    // test('the daps client should be able to validate the dat it got from the daps', async function () {
    //     const
    //         dat     = await dapsClient.fetchDat(),
    //         content = await dapsClient.validateDat(dat);
    //     expect(typeof content).toBe('object');
    //     console.log(content);
    // });

    test('the daps client should be able to get a dat', async function () {
        const dat = await dapsClient.getDat();
        expect(typeof dat).toBe('string');
        console.log(dat);
    });

    test('the daps client should be able to get the jwks', async function () {
        const jwks = await dapsClient.getJwks();
        expect(Array.isArray(jwks?.keys)).toBeTruthy();
        console.log(jwks);
    });

    test('the daps client should be able to construct a https agent', async function () {
        const agent = dapsClient.createDatHttpsAgent({rejectUnauthorized: false});
        expect(agent).toBeInstanceOf(https.Agent);
        console.log(agent);
    });

}); // describe
