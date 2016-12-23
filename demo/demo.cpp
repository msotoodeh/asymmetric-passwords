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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <map>
#include "../client/APUser.h"
#include "../server/APVerifier.h"

typedef struct
{
    uint64_t last_access_time;
    std::string algo;
    std::string publicKey;
} user_info_record;

// db: map user id's to user_info_record
std::map<std::string, user_info_record> user_info_records;

//std::vector<user_record_info_t> user_info_db;

const char* GetErrorString(int err)
{
    switch (err)
    {
    case APVerifier::AP_SUCCESS     : return "SUCCESS";
    case APVerifier::AP_E_PARAMETER : return "Invalid parameter";
    case APVerifier::AP_E_FORMAT    : return "Invalid format";
    case APVerifier::AP_E_KEY       : return "Invalid key";
    case APVerifier::AP_E_ALGO      : return "Invalid/Unknown algorithm";
    case APVerifier::AP_E_TOKEN     : return "Invalid token";
    case APVerifier::AP_E_TIMESTAMP : return "Invalid timestamp";
    case APVerifier::AP_E_SIZE      : return "Item too short";
    case APVerifier::AP_E_B64_ITEM  : return "Invalid base64 item";
    case APVerifier::AP_E_SIGNATURE : return "Signature mismatch";
    case APVerifier::AP_E_EMPTY     : return "Item is empty";
    case APVerifier::AP_E_TIME      : return "Token time out of valid range";
    case APVerifier::AP_E_EXPIRED   : return "Token time expired";
    }
    return "Unexpected error code";
}

void print_time_value(const char* msg, uint64_t t)
{
    char buf[80];
    //strftime(buf, sizeof(buf), "%Y-%m-%d %X", localtime((time_t*)&t));
    //strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S", localtime((time_t*)&t));
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %z", localtime((time_t*)&t));
    printf("%s %lld (%s)\n", msg, t, buf);
}

const char* tag_name(unsigned int tag)
{
    switch (tag)
    {
    case AP_NEW_USER: 
        return "REGISTER NEW USER";
    case AP_USER_LOGIN:
        return "LOGIN";
    case AP_CHANGE_PASSWORD:
        return "CHANGE PASSWORD";
    case AP_RESET_PASSWORD:
        return "PASSWORD RESET";
    case AP_UPDATE_TOKEN:
        return "TOKEN UPDATE";
    case AP_CHALLENGE_RESPONSE:
        return "CHALLENGED RESPONSE";
    }
    return "???";
}

void print_verifier_state(APVerifier& v)
{
    printf(" Status(%s): %s\n", tag_name(v.getTag()), GetErrorString(v.getError()));
    if (v.getError() != APVerifier::AP_SUCCESS) 
    {
        return;
    }

    print_time_value(" token timestamp ... :", v.getTimestamp());
    /*
    size_t i, nItems = v.getItemCount();
    for (i = 0; i < nItems; i++)
    {
        printf(" %d - [%s]\n", (int)i, v.getItem(i).c_str());
    }
    printf("\n public key (verifier): %s\n", v.getPublicKey().c_str());
    */
}

void demoRegisterNewUser(
    const std::string& userid,
    const std::string& password,
    const std::string& domain)
{
    printf("\n-- CLIENT ---- REGISTER NEW USER ----------------------------\n");
    APUser user(userid, password, domain);
    printf(" user id ........... : %s\n", userid.c_str());
    printf(" password .......... : %s\n", password.c_str());
    printf(" domain ............ : %s\n", domain.c_str());
    printf(" public key ........ : %s\n", user.getPublicKey().c_str());

    std::string reg_token = user.registerNewUser("888-555-1234");
    printf(" token layout ...... : nu.timestamp.algo.public_key.pw_reset_info.signature\n");
    printf(" token: %s\n", reg_token.c_str());

    printf("\n~~ SERVER ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    APVerifier verifier = APVerifier();
    if (verifier.parseUserRegistrationToken(reg_token))
    {
        printf(" new user id ....... : %s\n", userid.c_str());
        printf(" public key ........ : %s\n", verifier.getPublicKey().c_str());

        // save new user record (if not exists already)
        //if (user_info_records.find((userid) == user_info_records.end())
        {
            user_info_record ui;
            ui.algo = verifier.getItem(2);
            ui.publicKey = verifier.getPublicKey();
            ui.last_access_time = verifier.getTimestamp();
            user_info_records[userid] = ui;
        }
    }
    print_verifier_state(verifier);
}

void demoUserLogin(
    const std::string& userid,
    const std::string& password,
    const std::string& domain)
{
    printf("\n-- CLIENT ---- LOGIN ----------------------------------------\n");
    APUser user(userid, password, domain);
    printf(" user id ........... : %s\n", userid.c_str());
    printf(" password .......... : %s\n", password.c_str());
    printf(" domain ............ : %s\n", domain.c_str());
    printf(" public key ........ : %s\n", user.getPublicKey().c_str());

    std::string login_token = user.login(600);
    printf(" token layout ...... : li.timestamp.duration.signature\n");
    printf(" token: %s\n", login_token.c_str());

    printf("\n~~ SERVER ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    // Locate user's public key
    user_info_record& ui = user_info_records[userid];
    if (ui.publicKey.empty())
    {
        printf(" USER ID '%s' NOT FOUND.\n", userid.c_str());
        return;
    }

    APVerifier verifier = APVerifier();
    if (verifier.setKey(ui.publicKey) == APVerifier::AP_SUCCESS &&
        verifier.parseUserLoginToken(login_token))
    {
        if (verifier.getTimestamp() < ui.last_access_time)
        {
            // Token re-use
            printf(" TOKEN-REUSE ....... : %lld\n", ui.last_access_time);
        }

        // SUCCESS
        printf(" user id ........... : %s\n", userid.c_str());
        printf(" public key ........ : %s\n", verifier.getPublicKey().c_str());
        print_time_value(" expiration time ... :", verifier.getExpirationTime());
        user_info_records[userid].last_access_time = verifier.getTimestamp();
    }
    print_verifier_state(verifier);
}

void demoChangeUserPassword(
    const std::string& userid,
    const std::string& old_password,
    const std::string& new_password,
    const std::string& domain)
{
    printf("\n-- CLIENT ---- CHANGE PASSWORD ------------------------------\n");
    APUser new_user(userid, new_password, domain);
    APUser old_user(userid, old_password, domain);
    printf(" user id ........... : %s\n", userid.c_str());
    printf(" old password ...... : %s\n", old_password.c_str());
    printf(" new password ...... : %s\n", new_password.c_str());
    printf(" domain ............ : %s\n", domain.c_str());
    printf(" new public key .... : %s\n", new_user.getPublicKey().c_str());
    std::string new_key_token = old_user.changePassword(new_user);
    printf(" token layout ...... : cp.timestamp.new_public_key.signature\n");
    printf(" token: %s\n", new_key_token.c_str());

    printf("\n~~ SERVER ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

    // Locate user's public key
    user_info_record& ui = user_info_records[userid];
    APVerifier verifier = APVerifier();
    if (verifier.setKey(ui.publicKey) == APVerifier::AP_SUCCESS &&
        verifier.parseChangePasswordToken(new_key_token))
    {
        // SUCCESS: Update user record
        user_info_records[userid].publicKey = verifier.getPublicKey();
        user_info_records[userid].last_access_time = verifier.getTimestamp();
    }
    else
    {
        // ERROR
    }

    print_verifier_state(verifier);
    printf(" new public key .... : %s\n", verifier.getPublicKey().c_str());
}

int main(int argc, char**argv)
{
    std::string userid      = "jack";
    std::string password    = "password";
    std::string domain      = "www.example.com";

    demoRegisterNewUser(userid, password, domain);
    demoUserLogin(userid, password, domain);
    demoUserLogin("joe", password, domain);
    demoUserLogin(userid, "WRONG-PASSWORD", domain);
    demoChangeUserPassword(userid, password, "new-password", domain);
    demoUserLogin(userid, "new-password", domain);

    printf("\n-----------------------------------------------------------------\n");
    return 0;
}
