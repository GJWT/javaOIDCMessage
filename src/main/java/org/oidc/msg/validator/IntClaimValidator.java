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

import org.oidc.msg.InvalidClaimException;

/**
 * A {@link ClaimValidator} for {@link Long}s.
 */
public class IntClaimValidator implements ClaimValidator<Long> {

  @Override
  public Long validate(Object value) throws InvalidClaimException {
    if (value instanceof Long) {
      return (Long) value;
    } // convert Integer to Long.
    if (value instanceof Integer) {
      return ((Integer) value).longValue();
    } // convert String to Long if possible and update the value.
    if (value instanceof String) {
      try {
        return Long.parseLong((String) value);
      } catch (NumberFormatException e) {
        // We mark the error in the end of case.
      }
    }
    throw new InvalidClaimException(String.format("Parameter '%s' is not of expected type", value));
  }

}