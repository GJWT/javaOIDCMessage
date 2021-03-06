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

package org.oidc.msg.oauth2;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link CCAccessTokenRequest}.
 */
public class CCAccessTokenRequestTest extends BaseMessageTest<CCAccessTokenRequest> {

  @Before
  public void setup() {
    message = new CCAccessTokenRequest();
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    message.addClaim("grant_type", "client_credentials");
    Assert.assertTrue(message.verify());
    Assert.assertEquals("client_credentials", message.getClaims().get("grant_type"));
  }

  @Test
  public void testFailureInvalidMandatoryParameter() throws InvalidClaimException {
    message.addClaim("grant_type", "not_client_credentials");
    Assert.assertFalse(message.verify());
  }

  @Test
  public void testFailureMissingMandatoryParameter() throws InvalidClaimException {
    // remove because default value is added automatically
    message.getClaims().remove("grant_type");
    Assert.assertFalse(message.verify());
  }

}
