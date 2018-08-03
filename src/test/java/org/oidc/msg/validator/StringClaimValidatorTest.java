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

public class StringClaimValidatorTest extends BaseClaimValidatorTest<StringClaimValidator> {

  @Before
  public void setup() {
    validator = new StringClaimValidator();
  }

  @Test
  public void testValidValue() throws InvalidClaimException {
    Assert.assertEquals("valid", validator.validate("valid"));
  }

  @Override
  @Test
  public void testEmptyString() throws InvalidClaimException {
    Assert.assertEquals("", validator.validate(""));
  }
}