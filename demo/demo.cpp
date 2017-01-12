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
#include <memory.h>
#include <time.h>
#include <map>
#include "../client/APUser.h"
#include "../server/APVerifier.h"
#include "../client/APKeyDerivation.h"  // for self-test

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
    printf("%s %llu (%s)\n", msg, t, buf);
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
            printf(" TOKEN-REUSE ....... : %llu\n", ui.last_access_time);
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

int SelfTest()
{
    int error_count = 0;
    // HMAC-SHA512 test vector from RFC4231 (test case 2)
    static const uint8_t hmac_sha512_tv1[64] =
    {
        0x16,0x4b,0x7a,0x7b,0xfc,0xf8,0x19,0xe2,0xe3,0x95,0xfb,0xe7,0x3b,0x56,0xe0,0xa3,
        0x87,0xbd,0x64,0x22,0x2e,0x83,0x1f,0xd6,0x10,0x27,0x0c,0xd7,0xea,0x25,0x05,0x54,
        0x97,0x58,0xbf,0x75,0xc0,0x5a,0x99,0x4a,0x6d,0x03,0x4f,0x65,0xf8,0xf0,0xe6,0xfd,
        0xca,0xea,0xb1,0xa3,0x4d,0x4a,0x6b,0x4b,0x63,0x6e,0x07,0x0a,0x38,0xbc,0xe7,0x37
    };

    // PBKDF2 test vectors from: https://github.com/Jither/PBKDF2/blob/master/Jither.PBKDF2.Test/PBKDF2DeriveBytesTest.cs
    static const uint8_t pbkdf2_key1[64] =
    {   // iterations = 1
        0x86,0x7f,0x70,0xcf,0x1a,0xde,0x02,0xcf,0xf3,0x75,0x25,0x99,0xa3,0xa5,0x3d,0xc4,
        0xaf,0x34,0xc7,0xa6,0x69,0x81,0x5a,0xe5,0xd5,0x13,0x55,0x4e,0x1c,0x8c,0xf2,0x52,
        0xc0,0x2d,0x47,0x0a,0x28,0x5a,0x05,0x01,0xba,0xd9,0x99,0xbf,0xe9,0x43,0xc0,0x8f,
        0x05,0x02,0x35,0xd7,0xd6,0x8b,0x1d,0xa5,0x5e,0x63,0xf7,0x3b,0x60,0xa5,0x7f,0xce
    };
    static const uint8_t pbkdf2_key2[64] =
    {   // iterations = 2
        0xe1,0xd9,0xc1,0x6a,0xa6,0x81,0x70,0x8a,0x45,0xf5,0xc7,0xc4,0xe2,0x15,0xce,0xb6,
        0x6e,0x01,0x1a,0x2e,0x9f,0x00,0x40,0x71,0x3f,0x18,0xae,0xfd,0xb8,0x66,0xd5,0x3c,
        0xf7,0x6c,0xab,0x28,0x68,0xa3,0x9b,0x9f,0x78,0x40,0xed,0xce,0x4f,0xef,0x5a,0x82,
        0xbe,0x67,0x33,0x5c,0x77,0xa6,0x06,0x8e,0x04,0x11,0x27,0x54,0xf2,0x7c,0xcf,0x4e
    };
    static const uint8_t pbkdf2_key4096[64] =
    {   // iterations = 4096
        0xd1,0x97,0xb1,0xb3,0x3d,0xb0,0x14,0x3e,0x01,0x8b,0x12,0xf3,0xd1,0xd1,0x47,0x9e,
        0x6c,0xde,0xbd,0xcc,0x97,0xc5,0xc0,0xf8,0x7f,0x69,0x02,0xe0,0x72,0xf4,0x57,0xb5,
        0x14,0x3f,0x30,0x60,0x26,0x41,0xb3,0xd5,0x5c,0xd3,0x35,0x98,0x8c,0xb3,0x6b,0x84,
        0x37,0x60,0x60,0xec,0xd5,0x32,0xe0,0x39,0xb7,0x42,0xa2,0x39,0x43,0x4a,0xf2,0xd5
    };

    uint8_t dk[64], mac[64];
    // HMAC-SHA512: rfc4321 test case 2
    if (APDigest::hmac((const uint8_t*)"Jefe", 4,
        (const uint8_t*)"what do ya want for nothing?", 28, mac, 64) != 64 ||
        memcmp(mac, hmac_sha512_tv1, 64) != 0)
    {
        error_count++;
        printf ("KAT error #%d: HMAC (1) failure.\n", error_count);
    }

    // PBKDF2-HMAC-SHA512
    APDigest::pbkdf2("password", 8, "salt", 4, 1, dk, sizeof(dk));
    if (memcmp(dk, pbkdf2_key1, sizeof(dk)) != 0)
    {
        error_count++;
        printf ("KAT error #%d: PBKDF2 (1) failure.\n", error_count);
    }
    APDigest::pbkdf2("password", 8, "salt", 4, 2, dk, sizeof(dk));
    if (memcmp(dk, pbkdf2_key2, sizeof(dk)) != 0)
    {
        error_count++;
        printf ("KAT error #%d: PBKDF2 (2) failure.\n", error_count);
    }
    APDigest::pbkdf2("password", 8, "salt", 4, 4096, dk, sizeof(dk));
    if (memcmp(dk, pbkdf2_key4096, sizeof(dk)) != 0)
    {
        error_count++;
        printf ("KAT error #%d: PBKDF2 (4096) failure.\n", error_count);
    }
    return error_count;
}

int main(int argc, char**argv)
{
    if (SelfTest() != 0 ) return 1;

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
