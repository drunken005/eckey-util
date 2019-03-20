const crypto = require('crypto-browserify');
const secureRandom = require('secure-random');
const EC = require('elliptic').ec;
const isHexadecimal = require('validator').isHexadecimal;

let ellipticCurve = new EC('secp256k1');

const sha256 = function (data) {
    return crypto.createHash("sha256").update(data).digest();
};

const sha256Twice = function (data) {
    let __tmp__ = crypto.createHash("sha256").update(data).digest();
    return sha256(__tmp__);
};

function ECKey() {

}

ECKey.createPrivate = function () {
    return Buffer.from(secureRandom(32)).toString('hex')
};

ECKey.createHash = function (signingInput) {
    return sha256Twice(signingInput);
};

ECKey.loadPrivateKey = function (rawPrivateKey) {
    if (rawPrivateKey.length === 66) {
        rawPrivateKey = rawPrivateKey.slice(0, 64)
    }
    return ellipticCurve.keyFromPrivate(rawPrivateKey)
};

ECKey.loadPublicKey = function (rawPublicKey) {
    return ellipticCurve.keyFromPublic(rawPublicKey, 'hex')
};

ECKey.getPublicKey = function (privateKey, compressed = true) {
    if (typeof privateKey !== 'string') {
        throw 'private key must be a string'
    }
    if (!isHexadecimal(privateKey)) {
        throw Error('private key must be a hex string')
    }
    if (privateKey.length === 66) {
        privateKey = privateKey.slice(0, 64)
    } else if (privateKey.length <= 64) {
        // do nothing
    } else {
        throw Error('private key must be 66 characters or less')
    }

    const keyPair = ellipticCurve.keyFromPrivate(privateKey);
    return keyPair.getPublic(compressed, 'hex')
};

ECKey.signHash = function (signingInputHash, rawPrivateKey) {
    // make sure the required parameters are provided
    if (!(signingInputHash && rawPrivateKey)) {
        throw new Error('a signing input hash and private key are all required')
    }
    // prepare the private key
    let privateKeyObject = ECKey.loadPrivateKey(rawPrivateKey);
    // calculate the signature
    let signatureObject = privateKeyObject.sign(signingInputHash),
        derSignature = Buffer.from(signatureObject.toDER());
    // return the DER-formatted signature
    return derSignature.toString('hex')
};

ECKey.sign = function (message, rawPrivateKey) {
    let hash = ECKey.createHash(message);
    return ECKey.signHash(hash, rawPrivateKey)
};

ECKey.verifyHash = function (signingInputHash, derSignatureBuffer, rawPublicKey) {
    // make sure the required parameters are provided
    if (!(signingInputHash && derSignatureBuffer && rawPublicKey)) {
        throw new Error('a signing input hash, der signature, + public key are required')
    }
    // prepare the public key
    let publicKeyObject = ECKey.loadPublicKey(rawPublicKey);
    // verify the token
    return publicKeyObject.verify(signingInputHash, derSignatureBuffer)
};

ECKey.verify = function (message, signed, rawPublicKey) {
    return ECKey.verifyHash(ECKey.createHash(message), Buffer.from(signed, 'hex'), rawPublicKey);
};


module.exports = ECKey;