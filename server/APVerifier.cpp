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
#include <stdio.h>
#include <time.h>
#include <sstream>
#include "APVerifier.h"
#include "base64.h"
#include "APPublicKey.h"

APVerifier::APVerifier()
    : m_public_key(0)
    , m_error(AP_E_KEY)
    , m_tag(0)
    , m_token_timestamp(0)
    , m_token_expiration_time(0)
    , m_items()
{
}

APVerifier::~APVerifier(void)
{
    m_items.clear();
}

int APVerifier::setKey(const std::string& keyStr)
{
    unsigned char key[APPublicKey::PublicKeySize];
    do
    {
        if (B64Decode(keyStr, key, sizeof(key)) != sizeof(key))
        {
            m_error = AP_E_B64_ITEM;
            break;
        }

        m_public_key.setKey(key);
        m_error = AP_SUCCESS;

    } while(0);
    return m_error;
}

const std::string APVerifier::getPublicKey() const
{
    return B64Encode(m_public_key.getKey(), APPublicKey::PublicKeySize);
}

static int get_hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

const char* hex_string_to_u64(const char* p, uint64_t& val)
{
    val = 0;
    do
    {
        int d = get_hex_digit(*p);
        if (d < 0) break;

        p++;
        val = (val << 4) + d;
    } while(1);
    return p;
}

int APVerifier::SplitToken(const std::string& token)
{
    std::istringstream t(token);
    std::string s;
    m_items.clear();
    while (std::getline(t, s, AP_SEP)) m_items.push_back(s);

    if (m_items.size() < 3 || m_items[0].length() != 2)
        return AP_E_FORMAT;

    const char* p = m_items[0].c_str();
    m_tag = ((unsigned char)p[0] << 8) | (unsigned char)p[1];

    // Next item is timestamp (in hex format)
    p = hex_string_to_u64(m_items[1].c_str(), m_token_timestamp);
    if (*p != '\0') return AP_E_TIMESTAMP;

    // Validate timestamp against verifier time
    // Allow maximum of 30 mins difference
    uint64_t time_now = (uint64_t)time(NULL);

    if (m_token_timestamp > time_now)
    {
        // Token time is in future!!
        // We assume client time is not set accurately
        if (m_token_timestamp > (time_now + APV_MAX_TOKEN_TIME_DIFF))
            return AP_E_TIME;
    }
    else
    {
        if (time_now > (m_token_timestamp + APV_MAX_TOKEN_TIME_DIFF))
            return AP_E_TIME;
    }

    return AP_SUCCESS;
}

int APVerifier::ValidateToken(
    const std::string& token,
    size_t key_index)
{
    unsigned char sig[64];

    do
    {
        m_error = SplitToken(token);
        if (m_error != AP_SUCCESS) break;

        size_t nItems = m_items.size();

        // Last item is the signature in base64 format
        std::string& signature = m_items[nItems-1];
        if (B64Decode(signature, sig, sizeof(sig)) != sizeof(sig))
        {
            m_error = AP_E_B64_ITEM;
            break;
        }

        // If self-sined, key_index points to the public key
        if (key_index > 0)
        {
            if (key_index < 2 || key_index >= (nItems - 1))
            {
                m_error = AP_E_PARAMETER;
                break;
            }
            if (setKey(m_items[key_index]) != AP_SUCCESS) break;
        }

        m_error = m_public_key.verifySignature(
            (const unsigned char*)token.c_str(), 
            token.length() - signature.length(), 
            &sig[0]) ? 
            AP_SUCCESS : AP_E_SIGNATURE;

    } while(0);
    return m_error;
}

static const std::string emptyString = "";

const std::string& APVerifier::getItem(size_t index) const
{
    if (index < m_items.size()) 
        return m_items[index];

    return emptyString;
}

bool APVerifier::isActive() const
{
    return (isValid() && m_token_expiration_time > (uint64_t)time(NULL));
}

bool APVerifier::parseUserRegistrationToken(
    const std::string& token)
{
    m_error = SplitToken(token);
    if (m_error == AP_SUCCESS)
    {
        if (m_items.size() < 4)
            m_error = AP_E_FORMAT;
        else if (m_tag != AP_NEW_USER)
            m_error = AP_E_TOKEN;
        else if (m_items[2] != AP_DEFAULT_ALGO)
            m_error = AP_E_ALGO;
        else
            setKey(m_items[3]);
    }
    m_token_expiration_time = 0;
    return isValid();
}

bool APVerifier::parseUserLoginToken(const std::string& token)
{
    do
    {
        if (ValidateToken(token) != AP_SUCCESS) break;

        if (m_tag != AP_USER_LOGIN)
        {
            m_error = AP_E_TOKEN;
            break;
        }

        // item(2) is token duration (in hex)
        uint64_t duration = 0;
        const char* p = hex_string_to_u64(m_items[2].c_str(), duration);
        if (*p != '\0' || duration > APV_MAX_LOGIN_DURATION)
        {
            m_error = AP_E_TIMESTAMP;
            break;
        }

        m_token_expiration_time = (uint64_t)time(NULL) + duration;

    } while(0);
    return isValid();
}

bool APVerifier::parseChangePasswordToken(const std::string& token)
{
    if (ValidateToken(token) == AP_SUCCESS)
    {
        if (m_tag == AP_CHANGE_PASSWORD)
            setKey(getItem(2)); // Change public key
        else
            m_error = AP_E_TOKEN;
    }
    return isValid();
}
