const createHash = require('create-hash');
const randomBytes = require('randombytes');
const EC = require('elliptic').ec;

let ellipticCurve = new EC('secp256k1');

function _typeof(obj) {
    if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") {
        _typeof = function _typeof(obj) {
            return typeof obj;
        };
    } else {
        _typeof = function _typeof(obj) {
            return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj;
        };
    }
    return _typeof(obj);
}

function _assertString(input) {
    let isString = typeof input === 'string' || input instanceof String;

    if (!isString) {
        let invalidType;

        if (input === null) {
            invalidType = 'null';
        } else {
            invalidType = _typeof(input);

            if (invalidType === 'object' && input.constructor && input.constructor.hasOwnProperty('name')) {
                invalidType = input.constructor.name;
            } else {
                invalidType = "a ".concat(invalidType);
            }
        }

        throw new TypeError("Expected string but received ".concat(invalidType, "."));
    }
}

const hexadecimal = /^[0-9A-F]+$/i;

function _isHexadecimal(str) {
    (0, _assertString)(str);
    return hexadecimal.test(str);
}


function ECKey() {
}

module.exports = ECKey;

ECKey.secureRandom = function (count, options) {
    options = options || {type: 'Array'};
    let buf = randomBytes(count);

    switch (options.type) {
        case 'Array':
            return [].slice.call(buf);
        case 'Buffer':
            return buf;
        case 'Uint8Array':
            let arr = new Uint8Array(count);
            for (let i = 0; i < count; ++i) {
                arr[i] = buf.readUInt8(i)
            }
            return arr;
        default:
            throw new Error(options.type + " is unsupported.")
    }
};

ECKey.sha256 = function (data) {
    return createHash("sha256").update(data).digest();
};

ECKey.sha256Twice = function (data) {
    let __tmp__ = createHash("sha256").update(data).digest();
    return ECKey.sha256(__tmp__);
};

//ECKey.createHash
ECKey.createHash = createHash;

ECKey.createPrivate = function () {
    return Buffer.from(ECKey.secureRandom(32)).toString('hex')
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
    if (!_isHexadecimal(privateKey)) {
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
    let hash = ECKey.sha256Twice(message);
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
    return ECKey.verifyHash(ECKey.sha256Twice(message), Buffer.from(signed, 'hex'), rawPublicKey);
};