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

import com.google.common.base.Strings;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.oidc.msg.InvalidClaimException;

/**
 * A {@link ClaimValidator} for a list of strings.
 */
public class ListClaimValidator implements ClaimValidator<List<String>> {

  @Override
  @SuppressWarnings("unchecked")
  public List<String> validate(Object value) throws InvalidClaimException {
    if (value instanceof List) {
      List<?> list = (List<?>) value;
      if (list.isEmpty()) {
        return new ArrayList<String>();
      }
      if (list.get(0) instanceof String) {
        return (List<String>) value;
      }
    }
    if (value instanceof String && !Strings.isNullOrEmpty((String) value)) {
      return Arrays.asList((String) value);
    }
    throw new InvalidClaimException(String.format("Parameter '%s' is not of expected type", value));
  }

}