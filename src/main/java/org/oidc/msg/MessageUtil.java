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

package org.oidc.msg;

import com.auth0.jwt.exceptions.JWTDecodeException;

/**
 * Collection of utility methods related to messages.
 */
public final class MessageUtil {

  private MessageUtil() {
    // no op
  }

  /**
   * Splits the given token on the "." chars into a String array with 3 parts.
   *
   * @param token The string to split. Expected to have at least two parts.
   * @return the array representing the 3or parts of the token.
   * @throws JWTDecodeException if the given token doesn't have 2 (empty signature) or 3 parts.
   */
  public static String[] splitToken(String token) throws JWTDecodeException {
    String[] parts = token.split("\\.");
    if (parts.length == 2 && token.endsWith(".")) {
      // Tokens with alg='none' have empty String as Signature.
      parts = new String[] { parts[0], parts[1], "" };
    }
    if (parts.length != 3) {
      throw new JWTDecodeException(String
          .format("The token was expected to have 3 parts, but got %s.", parts.length));
    }

    return parts;
  }
}
