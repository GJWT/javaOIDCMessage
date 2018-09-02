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

import com.auth0.jwt.exceptions.oicmsg_exceptions.DeserializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.msg.Key;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link KeyClaimValidator}.
 */
public class KeyClaimValidatorTest extends BaseClaimValidatorTest<KeyClaimValidator> {

  @Before
  public void setup() {
    validator = new KeyClaimValidator();
  }

  @Test
  public void testValidValue() throws InvalidClaimException {
    Assert.assertTrue(validator.validate(new MockKey()) instanceof Key);
  }

  @Test(expected = InvalidClaimException.class)
  public void testInvalidValue() throws InvalidClaimException {
    validator.validate("somethingelse");
  }

  class MockKey extends Key {

    @Override
    public void deserialize() throws DeserializationNotPossible {
    }

    @Override
    public java.security.Key getKey(Boolean arg0) throws ValueError {
      return null;
    }

    @Override
    public boolean isPrivateKey() {
      return false;
    }

    @Override
    public Map<String, Object> serialize(boolean arg0) throws SerializationNotPossible {
      return null;
    }
  }
}