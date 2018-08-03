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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link ListClaimValidator}.
 */
public class ListClaimValidatorTest extends BaseClaimValidatorTest<ListClaimValidator> {

  @Before
  public void setup() {
    validator = new ListClaimValidator();
  }

  @Test(expected = InvalidClaimException.class)
  public void testInvalidList() throws InvalidClaimException {
    validator.validate(Arrays.asList(123L, 234L));
  }

  @Test
  public void testValidValue() throws InvalidClaimException {
    Assert.assertEquals(Arrays.asList("mock"), validator.validate("mock"));
    Assert.assertEquals(Arrays.asList("mock"), validator.validate(Arrays.asList("mock")));
  }

  @Test
  public void testEmptyListWriteable() throws InvalidClaimException {
    List<String> list = validator.validate(Collections.unmodifiableList(new ArrayList<Object>()));
    Assert.assertTrue(list.isEmpty());
    list.add("mock");
    Assert.assertEquals("mock", list.get(0));
  }

}