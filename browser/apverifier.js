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

var AP_ALGO_ED25519             = "ed255";    // ed25519-hmac-sha512
var AP_ALGO_ECDSA_SECP256R1     = "p256";     // secp256r1-hmac-sha256
var AP_ALGO_ECDSA_SECP256K1     = "k256";     // secp256k1-hmac-sha256
var AP_TAG_NEW_USER             = "nu";
var AP_TAG_CHANGE_PASSWORD      = "cp";
var AP_TAG_RESET_PASSWORD       = "rp";
var AP_TAG_USER_LOGIN           = "li";
var AP_TAG_UPDATE_TOKEN         = "ut";
var AP_TAG_CHALLENGE_RESPONSE   = "cr";

// Error codes
var AP_SUCCESS       =  0;
var AP_E_PARAMETER   = -1;
var AP_E_FORMAT      = -2;
var AP_E_ALGO        = -3;
var AP_E_TOKEN       = -4;
var AP_E_TIMESTAMP   = -5;
var AP_E_KEY         = -6;
var AP_E_SIZE        = -7;
var AP_E_SIGNATURE   = -8;
var AP_E_EMPTY       = -9;
var AP_E_B64_ITEM    = -10;
var AP_E_TIME        = -11;
var AP_E_EXPIRED     = -12;

// Max time difference between client & server
var APV_MAX_TOKEN_TIME_DIFF = 30*60*1000;   // 30 minutes max

function utf8StringToU8Array(str) {
    var bytes = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}

// url-safe base64 encoder/decoder
var b64table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function b64encode(byteArray) {
    var accu = 0, bits = 0, o = "";
    for (var i = 0; i < byteArray.length; i++) {
        accu = (accu << 8) | (byteArray[i] & 0xff);
        bits += 8;

        while (bits >= 6) {
            bits -= 6;
            o = o + b64table[(accu >>> bits) & 0x3f];
        }
    }
    // flush remaining bits (if any)
    if (bits > 0) o = o + b64table[(accu << (6 - bits)) & 0x3f];
    return o;
}

function b64decode(b64string) {
    var accu = 0, bits = 0, n = 0, index = 0;
    var bytes = [];
    while (true) {
        while (bits < 8) {
            if (index >= b64string.length) return new Uint8Array(bytes);
            var c = b64table.indexOf(b64string.charAt(index++));
            if (c < 0 || c > 63) return new Uint8Array(bytes);
            accu = (accu << 6) + c;
            bits += 6;
        }

        bits -= 8;
        bytes[n++] = (accu >>> bits) & 0xff;
    }
}

function apUserState(token) {
    this.token = token;
    this.items = token.split('.');
    this.tokenArrivalTime = Date.now();
    this.tokenExpirationTime = 0; // set by login token
    this.tokenTime = parseInt(this.getItem(1), 16) * 1000;
    this.error = AP_SUCCESS;
}

apUserState.prototype.verifySignature = function(publicKey) {
    var sig = this.getItem(this.items.length-1);
    var msg = utf8StringToU8Array(this.token.substring(0, this.token.length - sig.length));
    if (!nacl.sign.detached.verify(msg, b64decode(sig), b64decode(publicKey))) {
        this.error = AP_E_SIGNATURE;
        return false;
    }
    return true;
}

apUserState.prototype.isValid = function() {
    if (this.error == AP_SUCCESS && Date.now() < this.tokenExpirationTime) {
        this.error = AP_E_EXPIRED;
    }
    return (this.error == AP_SUCCESS);
}

apUserState.prototype.getItem = function(index) {
    return (index >= 0 && index < this.items.length) ? this.items[index] : "";
}

apUserState.prototype.checkNewUserToken = function() {
    // token format: tag.timestamp.algo.publicKey.nonce.signature
    if (this.items.length < 5 || this.items[0] !== "nu") {
        this.error = AP_E_TOKEN;
        return false;
    }
    if (this.items[2] !== AP_ALGO_ED25519) {
        this.error = AP_E_ALGO;
        return false;
    }
    // this token is self-signed
    return this.verifySignature(this.items[3]);
}

apUserState.prototype.checkUserLoginToken = function(publicKey, lastTokenTime) {
    // token format: tag.timestamp.duration.nonce.signature
    if (this.items.length < 4 || this.items[0] !== "li") {
        this.error = AP_E_TOKEN;
        return false;
    }
    // validate token timestamp
    if (Math.abs(this.tokenArrivalTime - this.tokenTime) > APV_MAX_TOKEN_TIME_DIFF ||
        this.lastTokenTime < lastTokenTime) {
        this.error = AP_E_TIME;
        return false;
    }
    this.tokenExpirationTime = this.tokenArrivalTime + parseInt(this.items[2], 16) * 1000;
    if (!this.verifySignature(publicKey))
    {
        this.error = AP_E_SIGNATURE;
        return false;
   }
   return true;
}

apUserState.prototype.checkChangePasswordToken = function(oldPublicKey, lastTokenTime) {
    // token format: tag.timestamp.newPublicKey.nonce.signature
    if (this.items.length < 4 || this.items[0] !== "cp") {
        this.error = AP_E_TOKEN;
        return false;
    }
    // validate token timestamp
    if (Math.abs(this.tokenArrivalTime - this.tokenTime) > APV_MAX_TOKEN_TIME_DIFF ||
        this.lastTokenTime < lastTokenTime) {
        this.error = AP_E_TIME;
        return false;
    }
    if (!this.verifySignature(oldPublicKey))
    {
        this.error = AP_E_SIGNATURE;
        return false;
   }
   return true;
}
