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

package org.oidc.msg.oidc;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link AccessTokenRequest}.
 */
public class AccessTokenRequestTest extends org.oidc.msg.oauth2.AccessTokenRequestTest {

  @Override
  @Before
  public void setup() {
    message = new AccessTokenRequest();
  }

  @Test(expected = InvalidClaimException.class)
  public void testInvalidClientAssertionType() throws InvalidClaimException {
    message.addClaim("code", "mockCode");
    message.addClaim("redirect_uri", "mockUri");
    message.addClaim("client_assertion_type", "invalid_value");
    message.verify();
  }

  @Test
  public void testValidClientAssertionType() throws InvalidClaimException {
    message.addClaim("code", "mockCode");
    message.addClaim("redirect_uri", "mockUri");
    message.addClaim("client_assertion_type",
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    Assert.assertTrue(message.verify());
    Assert.assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        message.getClaims().get("client_assertion_type"));
  }

}
