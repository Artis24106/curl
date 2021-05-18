/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curlcheck.h"

#include "curl_md5.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{

}

UNITTEST_START

#ifndef CURL_DISABLE_CRYPTO_AUTH
  const char string1[] = "1";
  const char string2[] = "hello-you-fool";
  const char string3[] = "I-thought-I-found-a-7th-dog,-but-it-was-actually-just-the-3rd-dog.I-thought-I-found-a-7th-dog,-but-it-was-actually-just-the-3rd-dog.I-thought-I-found-a-7th-dog,-but-it-was-actually-just-the-3rd-dog.I-thought-I-found-a-7th-dog,-but-it-was-actually-just-the-3rd-dog.I-thought-I-found-a-7th-dog,-but-it-was-actually-just-the-3rd-dog.I-thought-I-found-a-7th-dog,-but-it-was-actually-just-the-3rd-dog.I-thought-I-found-a-7th-dog,-but-it-was-actually-just-the-3rd-dog.I-thought-I-found-a-7th-dog,-but-it-was-actually-just-the-3rd-dog.I-thought-I-found-a-7th-dog,-but-it-was-actually-just-the-3rd-dog.I-thought-I-found-a-7th-dog,-but-it-was-actually-just-the-3rd-dog.";
  unsigned char output[MD5_DIGEST_LEN];
  unsigned char *testp = output;

  /* 1F, 2F, 4F, 5F */
  Curl_md5it(output, (const unsigned char *) string1, strlen(string1));

  verify_memory(testp, "\xc4\xca\x42\x38\xa0\xb9\x23\x82\x0d\xcc\x50\x9a\x6f"
                "\x75\x84\x9b", MD5_DIGEST_LEN);

  Curl_md5it(output, (const unsigned char *) string2, strlen(string2));

  verify_memory(testp, "\x88\x67\x0b\x6d\x5d\x74\x2f\xad\xa5\xcd\xf9\xb6\x82"
                "\x87\x5f\x22", MD5_DIGEST_LEN);

  /* case3: 4T */
  Curl_md5it(output, (const unsigned char *) string3, strlen(string3));

  verify_memory(testp, "\x54\x99\x8b\x0c\xee\xfa\x94\xe6\x71\xa1\xb8\x7f\xb7"
                "\xf3\x0f\x37", MD5_DIGEST_LEN);

#endif


UNITTEST_STOP
