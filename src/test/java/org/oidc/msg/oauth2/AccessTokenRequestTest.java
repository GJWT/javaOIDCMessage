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
 * Unit tests for {@link AccessTokenRequest}.
 */
public class AccessTokenRequestTest extends BaseMessageTest<AccessTokenRequest> {

  @Before
  public void setup() {
    message = new AccessTokenRequest();
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    message.addClaim("code", "mockCode");
    message.addClaim("redirect_uri", "mockUri");
    message.verify();
    Assert.assertEquals("mockCode", message.getClaims().get("code"));
    Assert.assertEquals("mockUri", message.getClaims().get("redirect_uri"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureMissingCodeMandatoryParameter() throws InvalidClaimException {
    message.addClaim("redirect_uri", "mockUri");
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureMissingRedirectUriMandatoryParameter() throws InvalidClaimException {
    message.addClaim("code", "mockCode");
    message.verify();
  }

}