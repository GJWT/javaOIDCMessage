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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link ArrayClaimValidator}.
 */
public class ArrayClaimValidatorTest extends BaseClaimValidatorTest<ArrayClaimValidator> {

  @Before
  public void setup() {
    validator = new ArrayClaimValidator();
  }

  @Test
  public void testPlainString() throws InvalidClaimException {
    Assert.assertEquals("string", validator.validate("string"));
    Assert.assertEquals("string strong", validator.validate("string strong"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testEmptyArrayWithoutListsEnabled() throws InvalidClaimException {
    validator.validate(new String[0]);
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testEmptyArrayWithListsEnabled() throws InvalidClaimException {
    validator = new ArrayClaimValidator(true);
    validator.validate(new String[0]);
  }

  @Test
  public void testNonEmptyArray() throws InvalidClaimException {
    Assert.assertEquals("string", validator.validate(new String[] { "string" }));
    Assert.assertEquals("string strong", validator.validate(new String[] { "string", "strong" }));
  }

  @Override
  @Test
  public void testEmptyString() throws InvalidClaimException {
    Assert.assertEquals("", validator.validate(""));
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testListWithoutEnablingLists() throws InvalidClaimException {
    validator.validate(Arrays.asList("string1", "string2"));
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testEmptyListWithEnablingLists() throws InvalidClaimException {
    validator.validate(new ArrayList<>());
  }

  @Test(expected = InvalidClaimException.class)
  public void testInvalidListWithEnablingLists() throws InvalidClaimException {
    validator.validate(Arrays.asList(1, 2));
  }
  
  @Test
  public void testListWithEnablingLists() throws InvalidClaimException {
    validator = new ArrayClaimValidator(true);
    Assert.assertEquals("string", validator.validate(Arrays.asList("string")));
    Assert.assertEquals("string1 string2", validator.validate(Arrays.asList("string1 string2")));
  }

}