/* The MIT License (MIT)
 * 
 * Copyright (c) 2016, 2017 Mehdi Sotoodeh, KryptoLogik Inc.
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

#ifndef __asymmetric_passwords_kdf_h__
#define __asymmetric_passwords_kdf_h__

#include <stdint.h>
#include <string>
#include "curve25519/sha512.h"

///////////////////////////////////////////////////////////////////////////////////////////////////
class APDigest
{
public:
    enum {
        // sizes are based on SHA512
        BLOCK_SIZE = SHA512_CBLOCK, 
        DIGEST_SIZE = SHA512_DIGEST_LENGTH,
        KDF_ITERATIONS = 1000, 
    };

    APDigest();
    APDigest(const void* data, size_t size);
    ~APDigest();

    void init();
    void update(const void* data, size_t size);
    void finish();
    size_t finish(void* digest, size_t size);

    uint8_t* digest() { return &m_Digest[0]; }

    static size_t hmac(
        const uint8_t* key, size_t key_size, 
        const uint8_t* msg, size_t msg_size,
        uint8_t* mac, size_t mac_size);

    // PBKDF2-HMAC-SHA-512
    static void pbkdf2 (
        const void *password, size_t passwordLen,
        const void *salt, size_t saltLen,
        uint32_t iterations,
        uint8_t* dk, size_t dkLen);

    static void kdf(        
        const std::string& userid,
        const std::string& password,
        const std::string& domain,
        uint8_t* dk, size_t dkLen);

private:
    SHA512_CTX m_Ctx;
    uint8_t m_Digest[DIGEST_SIZE];
};

#endif // __asymmetric_passwords_kdf_h__
