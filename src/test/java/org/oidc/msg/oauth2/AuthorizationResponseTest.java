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

import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link AuthorizationResponse}.
 */
public class AuthorizationResponseTest extends BaseMessageTest<AuthorizationResponse> {

  Map<String, Object> claims = new HashMap<String, Object>();

  /**
   * Setup mandatory claims.
   */
  @Before
  public void setup() {
    message = new AuthorizationResponse();
    claims.clear();
    claims.put("code", "FOOCODEBAR");
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    message = new AuthorizationResponse(claims);
    Assert.assertTrue(message.verify());
    Assert.assertEquals("FOOCODEBAR", message.getClaims().get("code"));
  }

  @Test
  public void testSuccessOptionalParameters() throws InvalidClaimException {
    claims.put("state", "FOOSTATEBAR");
    claims.put("iss", "FOOISSBAR");
    claims.put("client_id", "FOOCLIENTBAR");
    message = new AuthorizationResponse(claims);
    message.setClientId("FOOCLIENTBAR");
    message.setIssuer("FOOISSBAR");
    Assert.assertTrue(message.verify());
    Assert.assertEquals("FOOSTATEBAR", message.getClaims().get("state"));
    Assert.assertEquals("FOOISSBAR", message.getClaims().get("iss"));
    Assert.assertEquals("FOOCLIENTBAR", message.getClaims().get("client_id"));
  }

  @Test
  public void testFailVerifyIssuerValue() throws InvalidClaimException {
    claims.put("iss", "FOOISSBAR");
    message = new AuthorizationResponse(claims);
    Assert.assertFalse(message.verify());
    Assert.assertEquals("iss", message.getError().getDetails().get(0).getParameterName());
  }

  @Test
  public void testFailVerifyClientValue() throws InvalidClaimException {
    claims.put("client_id", "FOOCLIENTBAR");
    message = new AuthorizationResponse(claims);
    Assert.assertFalse(message.verify());
    Assert.assertEquals("client_id", message.getError().getDetails().get(0).getParameterName());
  }

}