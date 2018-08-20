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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.AbstractMessage;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link MessageClaimValidator}.
 */
public class MessageClaimValidatorTest extends BaseClaimValidatorTest<MessageClaimValidator> {

  @Before
  public void setup() {
    validator = new MessageClaimValidator();
  }

  @Test
  public void testValidValue() throws InvalidClaimException {
    MockMessage message = new MockMessage();
    message.addClaim("mock", "value");
    Assert.assertEquals(1, validator.validate(message).getClaims().size());
    Assert.assertEquals("value", validator.validate(message).getClaims().get("mock"));
  }

  class MockMessage extends AbstractMessage {

    public MockMessage() {
      super(new HashMap<String, Object>());
    }

  }
}
