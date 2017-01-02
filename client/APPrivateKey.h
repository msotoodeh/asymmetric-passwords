/* The MIT License (MIT)
 * 
 * Copyright (c) 2016 Mehdi Sotoodeh, KryptoLogik Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the 
 * "Software"), to deal in the Software without restriction, including 
 * without limitation the rights to use, copy, modify, merge, publish, 
 * distribute, sublicense, and/or sell copies of the Software, and to 
 * permit persons to whom the Software is furnished to do so, subject to 
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included 
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __asymmetric_passwords_private_key_h__
#define __asymmetric_passwords_private_key_h__

#include <stdint.h>
#include <string>

class APPrivateKey
{
public:
    /* Convert password to private key */
    APPrivateKey(
        const std::string& userid,
        const std::string& password,
        const std::string& domain);

    ~APPrivateKey();
    
    enum { // For ED25519
        SharedSecretSize    = 32, 
        SecretKeySize       = 32, 
        PublicKeySize       = 32, 
        PrivateKeySize      = 64, 
        SignatureSize       = 64
    };

    std::string signMessage(const std::string& msg);
    std::string getPublicKey() const;

    APPrivateKey& operator=(const APPrivateKey& rhs);

private:
    unsigned char m_Key[PrivateKeySize];
};

#endif // __asymmetric_passwords_private_key_h__
