Please note that:
```
1. This directory contains experimental code and is not stable yet.
2. Current implementation is compatible with the C++ project.
3. Javascript crypto library is based on www.github.com/dchest/tweetnacl-js
   for ED25519 sign/verify operations (client & server).
4. Forward issues and comments to mehdisotoodeh@gmail.com.
```
The demo.html file contains client and server side code.
For client side, include:
```
    nacl-fast.min.js
    apcommon.js
    pbkdf2.js
    apclient.js
```
For server side, include:
```
    nacl-fast.min.js
    apcommon.js
    apverifier.js
```
