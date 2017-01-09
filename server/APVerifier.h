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

#ifndef __asymmetric_passwords_verifier_h__
#define __asymmetric_passwords_verifier_h__

/* Verifier side of AsymmetricPasswords */
#include <stdint.h>
#include <string>
#include <vector>
#include "asymmetric_pass.h"
#include "APPublicKey.h"

class APVerifier
{
public:
    enum ErrorCodes
    {
        AP_SUCCESS       =  0,
        AP_E_PARAMETER   = -1,
        AP_E_FORMAT      = -2,
        AP_E_ALGO        = -3,
        AP_E_TOKEN       = -4,
        AP_E_TIMESTAMP   = -5,
        AP_E_KEY         = -6,
        AP_E_SIZE        = -7,
        AP_E_SIGNATURE   = -8,
        AP_E_EMPTY       = -9,
        AP_E_B64_ITEM    = -10,
        AP_E_TIME        = -11,
        AP_E_EXPIRED     = -12,
    };

    enum {
        APV_TIME_TICKS              = 1, // 1 tick per seconds
        APV_MINUTES                 = 60*APV_TIME_TICKS,
        APV_HOURS                   = 60*APV_MINUTES,
        // Max difference between client and server times
        APV_MAX_TOKEN_TIME_DIFF     = 30*APV_MINUTES,
        APV_MAX_TOKEN_LATENCY       = 1*APV_MINUTES,
        APV_MAX_LOGIN_DURATION      = 1*APV_HOURS,
    };

    APVerifier();
    ~APVerifier();

    int setKey(const std::string& public_key);

    bool parseUserRegistrationToken(const std::string& token);
    bool parseUserLoginToken(const std::string& token);
    bool parseChangePasswordToken(const std::string& token);

    /* Properties */
    bool isValid() const { return m_error >= 0; }
    bool isActive() const;
    int getError() const { return m_error; }
    unsigned int getTag() const { return m_tag; }
    size_t getItemCount() const { return m_items.size(); }
    const std::string& getItem(size_t index) const;
    const std::string getPublicKey() const;
    uint64_t getTimestamp() const { return m_token_timestamp; }
    uint64_t getExpirationTime() const { return m_token_expiration_time; }

private:
    /*
    // non-zero key_index interpreted as self-signed token
    // key_index >= 2 points to the key item used for verification
    // new-user registration and reset-password use self-signed tokens
    */
    int ValidateToken(const std::string& token, size_t key_index = 0);
    int SplitToken(const std::string& token);

    APPublicKey    m_public_key;
    int             m_error;

    /* token parsing results */
    unsigned int    m_tag;
    /* token times are in seconds since 1/1/1970 UTC */
    uint64_t        m_token_timestamp;
    uint64_t        m_token_expiration_time;
    std::vector<std::string> m_items;
};

#endif // __asymmetric_passwords_verifier_h__
