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
 * Unit tests for {@link AccessTokenResponse}.
 */
public class AccessTokenResponseTest extends org.oidc.msg.oauth2.AccessTokenResponseTest {
  
  @Before
  public void setup() {
    message = new AccessTokenResponse();
  }

  @Test
  public void testValidIdToken() throws InvalidClaimException {
    //TODO: check JWT signature also
    message.addClaim("access_token", "mockToken");
    message.addClaim("token_type", "mockType");
    String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    message.addClaim("id_token", jwt);
    message.verify();
    Assert.assertEquals("mockToken", message.getClaims().get("access_token"));
    Assert.assertEquals("mockType", message.getClaims().get("token_type"));
    Assert.assertEquals(jwt, message.getClaims().get("id_token"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testInvalidIdToken() throws InvalidClaimException {
    message.addClaim("access_token", "mockToken");
    message.addClaim("token_type", "mockType");
    message.addClaim("id_token", "not_jwt");
    message.verify();
  }

}
