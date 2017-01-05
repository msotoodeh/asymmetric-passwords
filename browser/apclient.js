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

function apclient() {}

apclient.prototype.kdf = function(userid, passwd, domain, msg) {
    var derived_key = pbkdf2_hmac_sha512(
        utf8StringToU8Array(passwd), 
        utf8StringToU8Array(userid + "&" + domain), 
        1000, 32);
    var signKeys = nacl.sign.keyPair.fromSeed(derived_key);
    this.publicKey = signKeys.publicKey;
    this.privateKey = signKeys.secretKey;
    //console.log("publicKey = " + b64encode(this.publicKey)); 
    if (msg.callback) msg.callback(this); else {
        var token = this.genToken(msg);
        msg.showResults(this);
        msg.submit(userid, token);
    }
};

apclient.prototype.genToken = function(msg) {
    var ts = Math.floor(Date.now()/1000);
    var token = msg.tag + "." + ts.toString(16) + "." + msg.payload(this) + "." +
    
    // append random nonce
    Math.floor(Math.random() * 0x100000000).toString(16) +
    Math.floor(Math.random() * 0x100000000).toString(16) +
    Math.floor(Math.random() * 0x100000000).toString(16) + ".";
    
    var sig = nacl.sign.detached(utf8StringToU8Array(token), this.privateKey);
    return token + b64encode(sig);
};
