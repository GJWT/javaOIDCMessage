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

import java.util.Date;

import org.oidc.msg.InvalidClaimException;

/**
 * A {@link ClaimValidator} for {̛@link Date}s. The source value can be in {@link Date},
 * {@link Integer} or {@link Long}. The latter two formats are expected to be in epoch seconds.
 */
public class DateClaimValidator implements ClaimValidator<Date> {

  @Override
  public Date validate(Object value) throws InvalidClaimException {
    if (value instanceof Date) {
      return (Date) value;
    } // Convert Integer and Long to Date if possible.
    if (value instanceof Integer) {
      return new Date(((Integer) value).longValue() * 1000L);
    }
    if (value instanceof Long) {
      return new Date((Long) value * 1000L);
    }
    throw new InvalidClaimException(String.format("Parameter '%s' is not of expected type", value));
  }

}