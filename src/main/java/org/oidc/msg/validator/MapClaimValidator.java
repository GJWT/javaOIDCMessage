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

import java.util.HashMap;
import java.util.Map;

import org.oidc.msg.InvalidClaimException;

/**
 * A {@link ClaimValidator} for a {@link Map} containing string keys.
 */
public class MapClaimValidator implements ClaimValidator<Map<String, Object>> {

  @SuppressWarnings("unchecked")
  @Override
  public Map<String, Object> validate(Object value) throws InvalidClaimException {
    if (value instanceof Map) {
      Map<?, ?> map = (Map<?, ?>) value;
      if (map.isEmpty()) {
        return new HashMap<String, Object>();
      }
      Object key = map.keySet().iterator().next();
      if (!(key instanceof String)) {
        throw new InvalidClaimException("Unexpected key type in the map: " + key.getClass());
      }
      return (Map<String, Object>) map;
    }
    throw new InvalidClaimException(String.format("Parameter '%s' is not of expected type", value));
  }

}
