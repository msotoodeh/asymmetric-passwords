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
#include "asymmetric_pass.h"
#include "APPrivateKey.h"
#include "curve25519/ed25519_signature.h"
#include "curve25519/curve25519_mehdi.h"
#include "curve25519/sha512.h"
#include "base64.h"
#include "APKeyDerivation.h"

extern "C" 
{
// Refresh blinds using custom_tool project
#include "custom_blinds.h"
}

static const char kdf_separator = AP_KDF_SEP;

///////////////////////////////////////////////////////////////////////////////////////////////////
APPrivateKey::APPrivateKey(
        const std::string& userid,
        const std::string& password,
        const std::string& domain)
{
    struct
    {
        unsigned char Kpub[PublicKeySize];
        unsigned char sk[SecretKeySize];
    } d;

    APDigest::kdf(userid, password, domain, d.sk, sizeof(d.sk)); 
    ed25519_CreateKeyPair (d.Kpub, m_Key, &edp_genkey_blinding, d.sk);
    memset (&d, 0, sizeof(d));
}
 
APPrivateKey::~APPrivateKey()
{
    memset (m_Key, 0, sizeof(m_Key));
}

std::string APPrivateKey::getPublicKey() const
{
    return B64Encode(&m_Key[32], PublicKeySize);
}

std::string APPrivateKey::signMessage(const std::string& msg)
{
    unsigned char sig[SignatureSize];
    ed25519_SignMessage (sig, m_Key, &edp_signature_blinding,
        (const unsigned char*)msg.c_str(), msg.length());

    return B64Encode(sig, sizeof(sig));
}

APPrivateKey& APPrivateKey::operator=(const APPrivateKey& rhs)
{
    if (&rhs != this)
    {
        memcpy (m_Key, rhs.m_Key, sizeof(m_Key));
    }
    return *this;
}
