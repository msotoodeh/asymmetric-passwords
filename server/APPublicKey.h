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
#ifndef __asymmetric_passwords_public_key_h__
#define __asymmetric_passwords_public_key_h__

#include <stdint.h>

class APPublicKey
{
public:
    enum { PublicKeySize = 32, SignatureSize = 64 };

    APPublicKey(const unsigned char* PublicKey);
    ~APPublicKey();

    const unsigned char* getKey() const;
    void setKey(const unsigned char* key);

    bool verifySignature(
        const unsigned char* msg,           /* IN: [msg_size bytes] message to sign */
        size_t msg_size,                    /* IN: size of message */
        const unsigned char* signature);    /* IN: [64 bytes] signature (R,S) */

private:
    unsigned char m_Key[PublicKeySize];
};

#endif // __asymmetric_passwords_public_key_h__
