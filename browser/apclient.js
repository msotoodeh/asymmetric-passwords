// The MIT License (MIT)
// 
// Copyright (c) 2016, 2017 Mehdi Sotoodeh, KryptoLogik Inc.
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

var KDF_ITERATIONS = 100;

function apclient(userid, passwd, domain) {
    var derived_key = pbkdf2_hmac_sha512(
        strToU8Array(passwd), 
        strToU8Array(userid + "&" + domain),
        KDF_ITERATIONS, 32);
    var signKeys = nacl.sign.keyPair.fromSeed(derived_key);
    this.publicKey = b64encode(signKeys.publicKey);
    this.privateKey = signKeys.secretKey;
};

apclient.prototype.genToken = function(tag, payload) {
    var ts = Math.floor(Date.now()/1000);
    var token = tag + "." + ts.toString(16) + "." + payload + "." +
    
    // append random nonce
    Math.floor(Math.random() * 0x100000000).toString(16) +
    Math.floor(Math.random() * 0x100000000).toString(16) +
    Math.floor(Math.random() * 0x100000000).toString(16) + ".";
    
    var sig = nacl.sign.detached(strToU8Array(token), this.privateKey);
    return token + b64encode(sig);
};

apclient.prototype.createNewUserToken = function() {
    return this.genToken(AP_TAG_NEW_USER, AP_ALGO_ED25519 + "." + this.publicKey);
}

apclient.prototype.createUserLoginToken = function(duration) {
    return this.genToken(AP_TAG_USER_LOGIN, duration.toString(16));
}

apclient.prototype.createChangePasswordToken = function(newPublicKey) {
    return this.genToken(AP_TAG_CHANGE_PASSWORD, newPublicKey);
}
