const fs = require('fs'), path = require('path'), crypto = require('crypto');
exports.meta = require('./server.json');
exports.key = fs.readFileSync(path.join(__dirname, './server.key'));
exports.privateKey = crypto.createPrivateKey(exports.key);
exports.pub = fs.readFileSync(path.join(__dirname, './server.pub'));
exports.publicKey = crypto.createPublicKey(exports.pub);
exports.cert = fs.readFileSync(path.join(__dirname, './server.cert'));
Object.freeze(exports);