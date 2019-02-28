# ECKey utils
Elliptic curve signature, public and private key generation and public key verification are realized.
Signature algorithm ***ECDSA***

```bash
npm i eckey-util --save
```

#### Create private key
```js
const ECKey = require('eckey-util')
ECKey.createPrivate()
```

#### Get public key
```js
ECKey.getPublicKey(privateKey)
```

#### Sign
```js
let signed = ECKey.sign('Hello world!', privateKey)
```
#### SignHash
```js
let signed = ECKey.signHash(ECKey.createHash('Hello world!'), privateKey)
```

#### Verify
```js
ECKey.verify('Hello world!', signed, publicKey)
```

#### VerifyHash
```js
ECKey.verifyHash(ECKey.createHash('Hello world!'), Buffer.from(signed, 'hex'), publicKey)
```