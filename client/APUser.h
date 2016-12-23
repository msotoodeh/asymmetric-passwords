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

#ifndef __asymmetric_passwords_user_h__
#define __asymmetric_passwords_user_h__

#include <string>
#include "asymmetric_pass.h"
#include "APPrivateKey.h"

class APUser
{
public:
    APUser(
        const std::string& userid, 
        const std::string& password,
        const std::string& domain);

    ~APUser();

    // tag.timestamp.valid_for.signature
    const std::string login(uint64_t duration = 300);

    // tag.timestamp.algo.public_key.pw_reset_info.signature
    //   pw_reset_info may include contact info for reset-password
    const std::string registerNewUser(const std::string& pw_reset_info);

    // tag.timestamp.new_public_key.signature
    //  signature is generated using old_password
    const std::string resetPassword(const std::string& reset_code);

    // tag.timestamp.new_public_key.signature
    //  signature is generated using old_password
    const std::string changePassword(const APUser& new_key);

    const std::string createToken(
        const std::string& tag, 
        const std::string& payload);

    const std::string getPublicKey() const;

private:
    APPrivateKey  m_private_key;
};

#endif // __asymmetric_passwords_user_h__
