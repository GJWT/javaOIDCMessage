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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link MapClaimValidator}.
 */
public class MapClaimValidatorTest extends BaseClaimValidatorTest<MapClaimValidator> {

  @Before
  public void setup() {
    validator = new MapClaimValidator();
  }

  @Test(expected = InvalidClaimException.class)
  public void testInvalidMap() throws InvalidClaimException {
    Map<Long, Object> map = new HashMap<>();
    map.put(123L, "mock");
    validator.validate(map);
  }

  @Test
  public void testValidValue() throws InvalidClaimException {
    Map<String, Object> map = new HashMap<>();
    map.put("mock", "value");
    Assert.assertTrue(
        map.values().containsAll(((Map<String, Object>) validator.validate(map)).values()));
  }

  @Test
  public void testEmptyMapWriteable() throws InvalidClaimException {
    Map<String, Object> map = validator
        .validate(Collections.unmodifiableMap((new HashMap<Object, Object>())));
    Assert.assertTrue(map.isEmpty());
    map.put("test", "testvalue");
    Assert.assertEquals("testvalue", map.get("test"));
  }

}