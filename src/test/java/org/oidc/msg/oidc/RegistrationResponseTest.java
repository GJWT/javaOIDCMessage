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

import java.util.Arrays;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link RegistrationResponse}.
 */
public class RegistrationResponseTest extends BaseMessageTest<RegistrationResponse> {

  private List<String> redirectUris;

  private String clientId;

  @Before
  public void setup() {
    message = new RegistrationResponse();
    redirectUris = Arrays.asList("https://example.org/cb");
    clientId = "mockClientId";
    message.addClaim("redirect_uris", redirectUris);
    message.addClaim("client_id", clientId);
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    Assert.assertTrue(message.verify());
    Assert.assertEquals(redirectUris, message.getClaims().get("redirect_uris"));
    Assert.assertEquals(clientId, message.getClaims().get("client_id"));
  }

  @Test
  public void testMissingRegistrationClientUri() throws InvalidClaimException {
    message.addClaim("registration_access_token", "mockToken");
    Assert.assertFalse(message.verify());
    Assert.assertEquals(1, message.getError().getDetails().size());
    Assert.assertEquals("registration_client_uri",
        message.getError().getDetails().get(0).getParameterName());

  }

  @Test
  public void testMissingRegistrationAccessToken() throws InvalidClaimException {
    message.addClaim("registration_client_uri", "mockUri");
    Assert.assertFalse(message.verify());
    Assert.assertEquals(1, message.getError().getDetails().size());
    Assert.assertEquals("registration_access_token",
        message.getError().getDetails().get(0).getParameterName());
  }
}
