const Eckey = require('./lib/ECKey');


let secret = Eckey.createPrivate();
console.log(secret);
let pub = Eckey.getPublicKey(secret);
console.log(pub);

let me = Eckey.sha256Twice('drunken');


let res = Eckey.signHash(me, secret);
console.log(res);


let ver = Eckey.verifyHash(me, res, pub);
console.log(ver);

console.log(Eckey.createHash('sha256').update('drunken').digest());
