// The MIT License (MIT)
// 
// Copyright (c) 2017 Mehdi Sotoodeh, KryptoLogik Inc.
// 
// Permission is hereby granted, free of charge, to any person obtaining 
// a copy of this software and associated documentation files (the 
// "Software"), to deal in the Software without restriction, including 
// without limitation the rights to use, copy, modify, merge, publish, 
// distribute, sublicense, and/or sell copies of the Software, and to 
// permit persons to whom the Software is furnished to do so, subject to 
// the following conditions:
// 
// The above copyright notice and this permission notice shall be included 
// in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 

var BLOCK_SIZE = 128, DIGEST_SIZE = 64;
                  
function hmac_sha512(key, msg) {
    var i, 
        innerMsg = new Uint8Array(BLOCK_SIZE + msg.length),
        outerMsg = new Uint8Array(BLOCK_SIZE + DIGEST_SIZE);
    if (key.length > BLOCK_SIZE) { key = nacl.hash(key); }
    for (i = 0; i < key.length; i++) { 
        innerMsg[i] = key[i] ^ 0x36; outerMsg[i] = key[i] ^ 0x5c; }

    while (i < BLOCK_SIZE) { innerMsg[i] = 0x36; outerMsg[i++] = 0x5c; }
  
    innerMsg.set(msg, BLOCK_SIZE);    
    outerMsg.set(nacl.hash(innerMsg), BLOCK_SIZE);
    return nacl.hash(outerMsg);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
function pbkdf2_hmac_sha512(passwd, salt, iterations, keySize) {
    var i, j, k, nBlock = 0,
        iBlock = new Uint8Array(salt.length + 4),
        Ti = new Uint8Array(DIGEST_SIZE),
        mk = new Uint8Array(keySize);
        
    /* iBlock = [ Salt || INT (nBlock)]. */
    iBlock.set(salt);
    
    for (k = 0; k < keySize; k += DIGEST_SIZE) {
        nBlock++;
        iBlock[salt.length + 0] = (nBlock >>> 24) & 0xFF;
        iBlock[salt.length + 1] = (nBlock >>> 16) & 0xFF;
        iBlock[salt.length + 2] = (nBlock >>> 8) & 0xFF;
        iBlock[salt.length + 3] = nBlock & 0xFF;

        var h = hmac_sha512 (passwd, iBlock);
        Ti.set(h);
        for (i = 1; i < iterations; i++) {
            h = hmac_sha512(passwd, h);
            for (j = 0; j < DIGEST_SIZE; j++) Ti[j] ^= h[j];
        }
        for (i = 0; i < DIGEST_SIZE && (i+k) < keySize; i++) { mk[i+k] = Ti[i]; }
    }
    return mk;
}
