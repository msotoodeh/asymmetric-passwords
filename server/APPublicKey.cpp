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
#include <memory.h>
#include "APPublicKey.h"
#include "curve25519/ed25519_signature.h"

///////////////////////////////////////////////////////////////////////////////////////////////////

APPublicKey::APPublicKey(const unsigned char* publicKey)
{
    setKey(publicKey);
}

APPublicKey::~APPublicKey()
{
}

void APPublicKey::setKey(const unsigned char* key)
{
    if (key)
        memcpy(m_Key, key, sizeof(m_Key));
    else
        memset(m_Key, 0, sizeof(m_Key));
}

const unsigned char* APPublicKey::getKey() const
{
    return &m_Key[0];
}

bool APPublicKey::verifySignature(
    const unsigned char* msg,           /* IN: [msg_size bytes] message to sign */
    size_t msg_size,                    /* IN: size of message */
    const unsigned char* signature)     /* IN: [64 bytes] signature (R,S) */
{
    return ed25519_VerifySignature (signature, m_Key, msg, msg_size) == 1;
}
