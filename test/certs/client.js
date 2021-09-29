const fs = require('fs'), path = require('path'), crypto = require('crypto');
exports.meta = require('./client.json');
exports.key = fs.readFileSync(path.join(__dirname, './client.key'));
exports.privateKey = crypto.createPrivateKey(exports.key);
exports.pub = fs.readFileSync(path.join(__dirname, './client.pub'));
exports.publicKey = crypto.createPublicKey(exports.pub);
exports.cert = fs.readFileSync(path.join(__dirname, './client.cert'));
Object.freeze(exports);