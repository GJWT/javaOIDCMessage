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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link BooleanClaimValidator}.
 */
public class BooleanClaimValidatorTest extends BaseClaimValidatorTest<BooleanClaimValidator> {

  @Before
  public void setup() {
    validator = new BooleanClaimValidator();
  }

  @Test
  public void testValidString() throws InvalidClaimException {
    Assert.assertEquals(Boolean.TRUE, validator.validate("true"));
    Assert.assertEquals(Boolean.FALSE, validator.validate("false"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testInvalidString() throws InvalidClaimException {
    validator.validate("not_true_or_false");
  }

  @Test
  public void testBoolean() throws InvalidClaimException {
    Assert.assertEquals(Boolean.TRUE, validator.validate(Boolean.TRUE));
    Assert.assertEquals(Boolean.FALSE, validator.validate(Boolean.FALSE));
  }

}