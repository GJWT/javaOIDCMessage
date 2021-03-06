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

package org.oidc.msg.validator;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import org.oidc.msg.InvalidClaimException;

/**
 * A {@link ClaimValidator} for JWTs in {@link String}. The strings are tested whether they can be
 * decoded into {@link JWT}, but they are kept as {@link String}s without transformation.
 */
public class JWTClaimValidator implements ClaimValidator<String> {

  @Override
  public String validate(Object value) throws InvalidClaimException {
    if (!(value instanceof String)) {
      throw new InvalidClaimException(
          String.format("Parameter '%s' is not of expected type", value));
    }
    try {
      JWT.decode((String) value);
    } catch (JWTDecodeException e) {
      throw new InvalidClaimException(String.format("Parameter '%s' is not JWT", value));
    }
    return (String) value;
  }

}