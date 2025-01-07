const
  { describe, test } = require('mocha'),
  expect = require('expect'),
  https = require('https'),
  express = require('express'),
  fetch = require('node-fetch'),
  DAPSClient = require('../src/ids.client.daps.js'),
  _client = require('./certs/client.js'),
  _server = require('./certs/server.js');

// REM: node .\app\nrd-testbed\ec\ids\src\scripts\setup.omejdn-daps.js add-client --load .\lib\ids\ids.client.daps\test\certs\client.js

// REM : JLA ::: node C:\fua\DEVL\js\app\nrd-testbed\ec\ids\src\scripts\setup.omejdn-daps.js add-client --load C:\fua\DEVL\js\lib\ids\ids.client.daps\test\certs\client.js

describe.skip('ids.client.daps', function () {

  this.timeout(10e3);

  const
    //region DAPS
    dapsUrl = "http://localhost:4567",
    dapsTokenPath = "/token",
    dapsJwksPath = "/.well-known/jwks.json",
    dapsVcPath = "/vc"
    //endregion DAPS
    ;
  let
    dapsClient
    ;

  before('construct a daps client', function () {
    expect(typeof DAPSClient).toBe('function');
    dapsClient = new DAPSClient({
      dapsUrl: dapsUrl,
      dapsTokenPath: dapsTokenPath,
      dapsJwksPath: dapsJwksPath,
      dapsVcPath: dapsVcPath,
      SKIAKI: _client.meta.SKIAKI,
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
    const datAgent = dapsClient.createDatHttpsAgent({
      rejectUnauthorized: false
    });
    expect(datAgent).toBeInstanceOf(https.Agent);
    const headers = await new Promise((resolve, reject) => {
      const server = https.createServer({
        key: _server.key,
        cert: _server.cert
      }, (req, res) => {
        res.end();
        server.close();
        resolve(req.headers);
      });
      server.listen(8081);
      fetch('https://localhost:8081', { // REM : omejdn-DAPS
        agent: datAgent
      }).catch(reject);
    });
    expect(headers.authorization).toMatch(/^Bearer \S+$/i);
    console.log(headers.authorization);
  });

}); // describe
