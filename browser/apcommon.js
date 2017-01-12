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

function strToU8Array(str) {
    var c, bytes = [];
    for (var i = 0; i < str.length; i++) {
        c = str.charCodeAt(i);
        if (c < 0x0080) {
            bytes.push(c & 0x7F);
        } else if (c < 0x0800) {
            bytes.push(0xC0 | ((c >>  6) & 0x1F));
            bytes.push(0x80 | ((c >>  0) & 0x3F));
        } else {
            bytes.push(0xE0 | ((c >> 12) & 0x0F));
            bytes.push(0x80 | ((c >>  6) & 0x3F));
            bytes.push(0x80 | ((c >>  0) & 0x3F));
        }
    }
    return new Uint8Array(bytes);
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
