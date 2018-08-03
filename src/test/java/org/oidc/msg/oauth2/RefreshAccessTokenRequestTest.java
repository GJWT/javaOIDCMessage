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
 * Unit tests for {@link RefreshAccessTokenRequest}.
 */
public class RefreshAccessTokenRequestTest extends BaseMessageTest<RefreshAccessTokenRequest> {

  @Before
  public void setup() {
    message = new RefreshAccessTokenRequest();
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    message.addClaim("grant_type", "refresh_token");
    message.addClaim("refresh_token", "mockRefreshToken");
    message.verify();
    Assert.assertEquals("refresh_token", message.getClaims().get("grant_type"));
    Assert.assertEquals("mockRefreshToken", message.getClaims().get("refresh_token"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureInvalidGrantTypeMandatoryParameter() throws InvalidClaimException {
    message.addClaim("grant_type", "not_refresh_token");
    message.addClaim("refresh_token", "mockRefreshToken");
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureMissingRefreshTokenMandatoryParameter() throws InvalidClaimException {
    message.addClaim("grant_type", "refresh_token");
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureGrantTypeMissingMandatoryParameter() throws InvalidClaimException {
    // remove because default value is added automatically
    message.getClaims().remove("grant_type");
    message.addClaim("refresh_token", "mockRefreshToken");
    message.verify();
  }

}