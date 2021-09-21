const
    {describe, test} = require('mocha'),
    expect           = require('expect'),
    DAPSClient       = require('./ids.client.daps.js'),
    certs            = require('./cert'),
    crypto           = require("crypto");

describe('ids.client.daps', function () {

    test('exported module should be a class and instantiable', function () {
        expect(typeof DAPSClient).toBe('function');
        const dapsClient = new DAPSClient({
            dapsUrl: 'https://localhost:8081',
            SKI:     'DD:CB:FD:0B:93:84:33:01:11:EB:5D:94:94:88:BE:78:7D:57:FC:4A',
            AKI:     'keyid:CB:8C:C7:B6:85:79:A8:23:A6:CB:15:AB:17:50:2F:E6:65:43:5D:E8',
            key:     crypto.createPrivateKey(certs.client.private)
        });
        expect(dapsClient).toBeInstanceOf(DAPSClient);
    }); // test

}); // describe
