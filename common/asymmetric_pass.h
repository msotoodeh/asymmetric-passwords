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

#ifndef __asymmetric_passwords_h__
#define __asymmetric_passwords_h__

#define AP_ALGO_ED25519             "ed255"
#define AP_ALGO_ECDSA_P256          "p256"
#define AP_ALGO_ECDSA_P384          "p384"
#define AP_ALGO_ECDSA_P512          "p512"

#define AP_DEFAULT_ALGO             AP_ALGO_ED25519

#define AP_SEP                      '.'
#define AP_KDF_SEP                  '&'

/* Standard Tags */

#define AP_TAG_NEW_USER             "nu"
#define AP_TAG_CHANGE_PASSWORD      "cp"
#define AP_TAG_RESET_PASSWORD       "rp"
#define AP_TAG_USER_LOGIN           "li"
#define AP_TAG_UPDATE_TOKEN         "ut"
#define AP_TAG_CHALLENGE_RESPONSE   "cr"

/* ID's for supported Tags */

#define AP_NEW_USER                 (('n' << 8) | 'u')
#define AP_CHANGE_PASSWORD          (('c' << 8) | 'p')
#define AP_RESET_PASSWORD           (('r' << 8) | 'p')
#define AP_USER_LOGIN               (('l' << 8) | 'i')
#define AP_UPDATE_TOKEN             (('u' << 8) | 't')
#define AP_CHALLENGE_RESPONSE       (('c' << 8) | 'r')

/* Capabilities */
#define AP_CAPS_CHAL_RESP           (1 << 0)
#define AP_CAPS_ENCRYPT             (1 << 1)
#define AP_CAPS_DECRYPT             (1 << 2)

#endif // __asymmetric_passwords_h__
