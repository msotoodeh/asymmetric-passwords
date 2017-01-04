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

var webcrypto = window.crypto || window.msCrypto;
if (webcrypto.subtle) {
    console.log("Cryptography API Supported");
    if (webcrypto.subtle.deriveBits == undefined) {
        alert("Browser does not support 'deriveBits' method");
    }
} else {
    alert("Cryptography API NOT Supported");
}

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

function apclient() {}

apclient.prototype.kdf = function(userid, passwd, domain, msg) {
    var client = this;
    webcrypto.subtle.importKey(
        "raw",
        utf8StringToU8Array(passwd),
        { name: "PBKDF2", },
        false,
        ["deriveBits"]
    ).then(function(pwkey) {
        webcrypto.subtle.deriveBits(
            {
                "name": "PBKDF2",
                salt: utf8StringToU8Array(userid + "&" + domain),
                iterations: 1000,
                hash: {name: "SHA-512"},
            },
            pwkey,
            256 // key size to derive
        ).then(function(derived_key) {
            var signKeys = nacl.sign.keyPair.fromSeed(new Uint8Array(derived_key));
            client.publicKey = signKeys.publicKey;
            client.privateKey = signKeys.secretKey;
            //console.log("publicKey = " + b64encode(client.publicKey)); 
            if (msg.callback) msg.callback(client); else {
                var token = client.genToken(msg);
                msg.showResults(client);
                msg.submit(userid, token);
            }
        }).catch(function(err) {
            console.error(err);
        });
    }).catch(function(err){
        console.error(err);
    });
};

apclient.prototype.genToken = function(msg) {
    var ts = Math.floor(Date.now()/1000);
    var token = msg.tag + "." + ts.toString(16) + "." + msg.payload(this) + "." +
    
    // append random nonce
    Math.floor(Math.random() * 0x100000000).toString(16) +
    Math.floor(Math.random() * 0x100000000).toString(16) +
    Math.floor(Math.random() * 0x100000000).toString(16) + ".";
    
    //console.log("unsigned token:", token);
    var sig = nacl.sign.detached(utf8StringToU8Array(token), this.privateKey);
    //console.log("Signature:", b64encode(sig));
    return token + b64encode(sig);
};
