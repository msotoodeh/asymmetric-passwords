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
#include <memory.h>
#include "APKeyDerivation.h"
#include "asymmetric_pass.h"

static const char kdf_separator = AP_KDF_SEP;

///////////////////////////////////////////////////////////////////////////////////////////////////
APDigest::APDigest()
{
    init();
}

APDigest::APDigest(const void* data, size_t size)
{
    init();
    update(data, size);
    finish(m_Digest, sizeof(m_Digest));
}

APDigest::~APDigest()
{
    memset (&m_Ctx, 0, sizeof(m_Ctx));
    memset (m_Digest, 0, sizeof(m_Digest));
}


void APDigest::init()
{
    SHA512_Init(&m_Ctx);
}

void APDigest::update(const void* data, size_t size)
{
    SHA512_Update(&m_Ctx, data, size);
}

void APDigest::finish()
{
    SHA512_Final(m_Digest, &m_Ctx);
}

size_t APDigest::finish(void* digest, size_t size)
{
    SHA512_Final(m_Digest, &m_Ctx);
    if (size > DIGEST_SIZE) 
        size = DIGEST_SIZE;

    memcpy(digest, &m_Digest[0], size);
    return size;
}

size_t APDigest::hmac(
    const uint8_t* key, size_t key_size, 
    const uint8_t* msg, size_t msg_size,
    uint8_t* mac, size_t mac_size)
{
    uint32_t i;
    uint8_t i_pad[BLOCK_SIZE], o_pad[BLOCK_SIZE];
    if (key_size > BLOCK_SIZE)
    {
        APDigest h((void*)key, key_size);
        for (i = 0; i < DIGEST_SIZE; i++)
        {
            o_pad[i] = h.m_Digest[i] ^ 0x5c;
            i_pad[i] = h.m_Digest[i] ^ 0x36;
        }
    }
    else
    {
        for (i = 0; i < key_size; i++)
        {
            o_pad[i] = key[i] ^ 0x5c;
            i_pad[i] = key[i] ^ 0x36;
        }
    }

    while (i < BLOCK_SIZE)
    {
        o_pad[i] = 0x5c;
        i_pad[i] = 0x36;
        i++;
    }

    APDigest inner_hash;
    inner_hash.update((void*)&i_pad[0], sizeof(i_pad));
    inner_hash.update((void*)msg, msg_size);
    inner_hash.finish();

    APDigest outer_hash;
    outer_hash.update((void*)&o_pad[0], sizeof(o_pad));
    outer_hash.update((void*)&inner_hash.m_Digest[0], sizeof(inner_hash.m_Digest));
    return outer_hash.finish((void*)mac, mac_size);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
void APDigest::kdf(
    const std::string& userid,
    const std::string& password,
    const std::string& domain,
    uint8_t* dk, size_t dkLen)
{
#ifdef USE_PASSWORD_HASH
    // Replace password with its hash to be able to convert hashed
    // passwords automatically

    // Here we are assuming passwords are haded with sha512
    APDigest passwordHash(password.c_str(), password.length());

    // Use combination of userid & domain as salt

    APDigest saltHash;
    saltHash.update(userid.c_str(), userid.length());
    saltHash.update(&kdf_separator, 1);
    saltHash.update(domain.c_str(), domain.length());
    saltHash.finish();

    APDigest::pbkdf2(
        passwordHash.digest(), APDigest::DIGEST_SIZE, 
        saltHash.digest(), APDigest::DIGEST_SIZE,
        APDigest::KDF_ITERATIONS,
        dk, dkLen);
#else
    std::string salt = userid + AP_KDF_SEP + domain;
    APDigest::pbkdf2(
        password.c_str(), password.length(), 
        salt.c_str(), salt.length(),
        APDigest::KDF_ITERATIONS,
        dk, dkLen);
#endif
}

///////////////////////////////////////////////////////////////////////////////////////////////////
static void PRF(
   const uint8_t *password, size_t passwordLen,
   uint8_t *saltBlock, size_t saltLen,
   uint32_t iterations,
   uint32_t blockNumber,
   uint8_t *dk, size_t dkLen)   // dkLen <= APDigest::DIGEST_SIZE
{
    uint8_t mac[APDigest::DIGEST_SIZE];
    /* saltBlock = [ Salt || INT (blockNumber)]. */
    saltBlock[saltLen + 0] = (uint8_t)(blockNumber >> 24);
    saltBlock[saltLen + 1] = (uint8_t)(blockNumber >> 16);
    saltBlock[saltLen + 2] = (uint8_t)(blockNumber >> 8);
    saltBlock[saltLen + 3] = (uint8_t)(blockNumber);

    APDigest::hmac (
        password, passwordLen, 
        saltBlock, saltLen + 4, 
        mac, sizeof(mac));
    memcpy (dk, mac, dkLen);

    while (--iterations > 0)
    {
        APDigest::hmac (
            password, passwordLen, 
            mac, APDigest::DIGEST_SIZE, 
            mac, APDigest::DIGEST_SIZE);
        for (uint32_t i = 0; i < dkLen; i++) dk[i] ^= mac[i];
    }
}

void APDigest::pbkdf2(
    const void *password, size_t passwordLen,
    const void *salt,     size_t saltLen,
    uint32_t iterations,
    uint8_t* dk,          size_t dkLen)
{
    uint8_t *saltBlock = new uint8_t[saltLen + 4];
    uint32_t blockNumber = 1;
    memcpy (saltBlock, salt, saltLen);
    while (dkLen >= DIGEST_SIZE)
    {
        PRF((const uint8_t*)password, passwordLen, 
            saltBlock, saltLen,
            iterations, blockNumber++, dk, DIGEST_SIZE);
        dk += DIGEST_SIZE;
        dkLen -= DIGEST_SIZE;
    }

    if (dkLen > 0)
    {
        PRF((const uint8_t*)password, passwordLen, 
            saltBlock, saltLen,
            iterations, blockNumber, dk, dkLen);
    }
    delete [] saltBlock;
}

