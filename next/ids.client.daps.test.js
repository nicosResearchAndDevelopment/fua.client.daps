const
    {describe, test} = require('mocha'),
    expect           = require('expect'),
    DAPSClient       = require('./ids.client.daps.js'),
    certs            = require('./cert'),
    crypto           = require("crypto");

describe('ids.client.daps', function () {

    this.timeout(10e3);

    test('exported module should be a class and instantiable', function () {
        expect(typeof DAPSClient).toBe('function');
        const dapsClient = new DAPSClient({
            dapsUrl:    'http://localhost:4567',
            SKI:        'DD:CB:FD:0B:93:84:33:01:11:EB:5D:94:94:88:BE:78:7D:57:FC:4A',
            AKI:        'keyid:CB:8C:C7:B6:85:79:A8:23:A6:CB:15:AB:17:50:2F:E6:65:43:5D:E8',
            privateKey: crypto.createPrivateKey(certs.client.private)
        });
        expect(dapsClient).toBeInstanceOf(DAPSClient);
        console.log(dapsClient);
    }); // test

    test('the daps client should be able to fetch a new dat', async function () {
        const
            dapsClient = new DAPSClient({
                dapsUrl:    'http://localhost:4567',
                SKI:        'DD:CB:FD:0B:93:84:33:01:11:EB:5D:94:94:88:BE:78:7D:57:FC:4A',
                AKI:        'keyid:CB:8C:C7:B6:85:79:A8:23:A6:CB:15:AB:17:50:2F:E6:65:43:5D:E8',
                privateKey: crypto.createPrivateKey(certs.client.private)
            }),
            dat        = await dapsClient.fetchDat();
        expect(typeof dat).toBe('string');
        console.log(dat);
    });

    test('the daps client should be able to fetch the jwks', async function () {
        const
            dapsClient = new DAPSClient({
                dapsUrl:    'http://localhost:4567',
                SKI:        'DD:CB:FD:0B:93:84:33:01:11:EB:5D:94:94:88:BE:78:7D:57:FC:4A',
                AKI:        'keyid:CB:8C:C7:B6:85:79:A8:23:A6:CB:15:AB:17:50:2F:E6:65:43:5D:E8',
                privateKey: crypto.createPrivateKey(certs.client.private)
            }),
            jwks       = await dapsClient.fetchJwks();
        expect(Array.isArray(jwks?.keys)).toBeTruthy();
        console.log(jwks);
    });

}); // describe
