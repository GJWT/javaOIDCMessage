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

import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.UnknownKeyType;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.msg.Key;
import java.io.IOException;
import java.util.HashMap;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.SerializationException;

/**
 * Unit tests for {@link AccessTokenResponse}.
 */
public class AccessTokenResponseTest extends BaseMessageTest<AccessTokenResponse> {
  
  @Before
  public void setup() {
    message = new AccessTokenResponse();
  }

  @Test
  public void testValidIdToken() throws InvalidClaimException, IllegalArgumentException, ImportException, UnknownKeyType, ValueError, IOException, JWKException, SerializationException {
    //TODO: check JWT signature also
    message.addClaim("access_token", "mockToken");
    message.addClaim("token_type", "mockType");
    Key key = getKeyJarPrv().getSigningKey("RSA", keyOwner, null, null).get(0);
    String jwt = generateIdTokenNow(new HashMap<String, Object>(), key, "RS256");
    message.setIssuer(keyOwner);
    message.setKeyJar(getKeyJarPub());
    message.addClaim("id_token", jwt);
    Assert.assertTrue(message.verify());
    Assert.assertEquals("mockToken", message.getClaims().get("access_token"));
    Assert.assertEquals("mockType", message.getClaims().get("token_type"));
    Assert.assertEquals(jwt, message.getClaims().get("id_token"));
  }

  @Test
  public void testInvalidIdToken() throws InvalidClaimException {
    message.addClaim("access_token", "mockToken");
    message.addClaim("token_type", "mockType");
    message.addClaim("id_token", "not_jwt");
    Assert.assertFalse(message.verify());
  }

}
