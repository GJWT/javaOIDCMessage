/*
 * Copyright (C) 2018 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.oidc.msg.oidc.util;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;

/** Calculate SHA-2 value for at_hash and c_hash claims. */
public class TokenHash {

  private static MessageDigest getMessageDigest(String algorithm) {
    try {
      switch (algorithm) {
        case "HS256":
        case "ES256":
        case "RS256":
        case "PS256":
          return MessageDigest.getInstance("SHA-256");
        case "HS384":
        case "ES384":
        case "RS384":
        case "PS384":
          return MessageDigest.getInstance("SHA-384");
        case "HS512":
        case "ES512":
        case "RS512":
        case "PS512":
          return MessageDigest.getInstance("SHA-512");
        default:
          return null;
      }
    } catch (NoSuchAlgorithmException e) {
      return null;
    }
  }

  /**
   * Calculate at_hash or c_hash value. Its value is the base64url encoding of the left-most half of
   * the hash of the octets of the ASCII representation of the access_token/code value, where the
   * hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's
   * JOSE Header.
   * 
   * @param claim
   *          code or access_token
   * @param algorithm
   *          the algorithm used for signing the jwt.
   * @return SHA-2 value for at_hash/c_hash claim.
   */
  public static String compute(String claim, String algorithm) {
    MessageDigest md = getMessageDigest(algorithm);
    if (md == null) {
      return null;
    }
    md.update(claim.getBytes(Charset.forName("US-ASCII")));
    byte[] hashValue = md.digest();
    return Base64.encodeBase64URLSafeString(Arrays.copyOf(hashValue, hashValue.length / 2));
  }

}
