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
#include <stdint.h>
#include <time.h>
#include <sstream>
#include "APPrivateKey.h"
#include "APUser.h"
#include "base64.h"

APUser::APUser(
    const std::string& userid, 
    const std::string& password, 
    const std::string& domain)
    : m_private_key(userid,  password, domain)
{
}

APUser::~APUser() 
{
}

/* Create a token consisting of: tag.timestamp.payload.signature
 */
const std::string APUser::createToken(
    const std::string& tag, 
    const std::string& payload)
{
    std::ostringstream s;
    s << tag << AP_SEP << std::hex << uint64_t(time(0)) << AP_SEP << payload << AP_SEP;

    std::string p = s.str();
    return p + m_private_key.signMessage(p);
}

const std::string APUser::getPublicKey() const
{
    return m_private_key.getPublicKey();
}

// tag.timestamp.algo.public_key.reset_info.signature
//   reset_info may include contact info for reset-password
const std::string APUser::registerNewUser(
    const std::string& pw_reset_info)
{
    std::ostringstream payload;
    payload << AP_DEFAULT_ALGO << AP_SEP << getPublicKey();
    if (!pw_reset_info.empty())
        payload << AP_SEP << B64Encode(
            pw_reset_info.c_str(), pw_reset_info.length());
    return createToken(AP_TAG_NEW_USER, payload.str());
}

// tag.timestamp.new_public_key.signature
//  signature is generated using old_password
const std::string APUser::resetPassword(
    const std::string& pw_reset_code)
{
    std::ostringstream payload;
    payload << getPublicKey() << AP_SEP << pw_reset_code;
    return createToken(AP_TAG_RESET_PASSWORD, payload.str());
}

// tag.timestamp.new_public_key.signature
//  signature is generated using old_password
const std::string APUser::changePassword(
    const APUser& new_key)
{
    std::string payload = new_key.getPublicKey();
    std::string token = createToken(AP_TAG_CHANGE_PASSWORD, payload);
    m_private_key = new_key.m_private_key;
    return token;
}

// tag.timestamp.valid_for.signature
const std::string APUser::login(
    uint64_t duration)
{
    std::ostringstream payload;
    payload << std::hex << duration;
    return createToken(AP_TAG_USER_LOGIN, payload.str());
}

