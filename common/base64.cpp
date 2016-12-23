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

#include "base64.h"

static const char bin_to_base64[64] =
{
    // Using URL-safe characters
    // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q',
    'R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q',
    'r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9','-','_'
};

std::string B64Encode(const void* data, size_t size)
{
    uint32_t accu = 0, bits = 0;
    std::string os;
    for (size_t i = 0; i < size; i++) {
        accu = (accu << 8) | ((unsigned char*)data)[i];
        bits += 8;

        while (bits >= 6) {
            bits -= 6;
            os.append(1, bin_to_base64[(accu >> bits) & 0x3f]);
        }
    }
    if (bits > 0)
        os.append(1, bin_to_base64[(accu << (6 - bits)) & 0x3f]);
    return os;
}

std::string B64Encode(const std::string& str)
{
    return B64Encode((const unsigned char*)str.c_str(), str.length()+1);
}

enum {
    WS = 0x40,     /* White space */
    TR = 0x41,     /* Terminators */
    NV = 0x42,     /* Not valid */
};

static const unsigned char base64_to_bin[256] =
{
    TR,NV,NV,NV,NV,NV,NV,NV,NV,WS,WS,WS,WS,WS,NV,NV,    /* 00 */
    NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,    /* 10 */
    WS,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,62,NV,NV,    /* 20 */
    52,53,54,55,56,57,58,59,60,61,NV,NV,NV,TR,NV,NV,    /* 30 */
    NV, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,    /* 40 */
    15,16,17,18,19,20,21,22,23,24,25,NV,NV,NV,NV,63,    /* 50 */
    NV,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,    /* 60 */
    41,42,43,44,45,46,47,48,49,50,51,NV,NV,NV,NV,NV,    /* 70 */
    NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,    /* 80 */
    NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,    /* 90 */
    NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,    /* A0 */
    NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,    /* B0 */
    NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,    /* C0 */
    NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,    /* D0 */
    NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,    /* E0 */
    NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,NV,    /* F0 */
};

size_t B64Decode(const std::string& b64String, unsigned char* buffer, size_t size)
{
    size_t i;
    uint32_t ch, accu = 0, bits = 0, index = 0;
    for (i = 0; i < size; i++) {
        while (bits < 8) {
            do {
                ch = base64_to_bin[b64String[index++] & 0xff];
            } while (ch == WS);     // ignore white spaces

            if (ch >= 64) return i; // TR is expected here

            accu = (accu << 6) | ch;
            bits += 6;
        }

        bits -= 8;
        *buffer++ = (unsigned char)(accu >> bits);
    }
    return i;
}
