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

import java.util.Arrays;
import java.util.List;

import org.oidc.msg.InvalidClaimException;

/**
 * A {@link ClaimValidator} for an array of strings or space separated strings. Optionally also
 * supports a list of strings, which is disabled by default.
 */
public class ArrayClaimValidator implements ClaimValidator<String> {
  
  /** The flag to accept also list of strings in addition to the array. Defaults to false. */
  private boolean acceptLists;
  
  /**
   * Constructor.
   */
  public ArrayClaimValidator() {
    this(false);
  }
  
  /**
   * Constructor.
   * @param lists The flag to accept also list of strings in addition to the arrays.
   */
  public ArrayClaimValidator(boolean lists) {
    acceptLists = lists;
  }

  @SuppressWarnings("unchecked")
  @Override
  public String validate(Object value) throws InvalidClaimException {
    if (value instanceof String) {
      return (String) value;
    }
    if (!(value instanceof String[]) || ((String[]) value).length == 0) {
      if (acceptLists && (value instanceof List) && !((List<?>) value).isEmpty()) {
        List<?> list = (List<?>) value;
        if (list.get(0) instanceof String) {
          return buildFromList((List<String>) value);
        }
      }
      throw new InvalidClaimException(
          String.format("Parameter '%s' is not of expected type", value));
    }
    return buildFromList(Arrays.asList((String[]) value));
  }
  
  protected String buildFromList(List<String> list) {
    String spaceSeparatedString = "";
    for (String item : list) {
      spaceSeparatedString += spaceSeparatedString.length() > 0 ? " " + item : item;      
    }
    return spaceSeparatedString;
  }

}