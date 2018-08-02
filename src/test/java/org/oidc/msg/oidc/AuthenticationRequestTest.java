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
import com.auth0.jwt.exceptions.oicmsg_exceptions.UnknownKeyType;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.msg.Key;
import com.auth0.msg.KeyType;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;

public class AuthenticationRequestTest extends BaseMessageTest<AuthenticationRequest> {

  Map<String, Object> claims = new HashMap<String, Object>();
  
  /**
   * Setup mandatory claims.
   */
  @Before
  public void setup() {
    message = new AuthenticationRequest();
    claims.clear();
    claims.put("response_type", "code");
    claims.put("client_id", "value");
    claims.put("redirect_uri", "value");
    claims.put("scope", "openid");
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    message = new AuthenticationRequest(claims);
    message.verify();
    Assert.assertEquals("code", message.getClaims().get("response_type"));
    Assert.assertEquals("value", message.getClaims().get("client_id"));
    Assert.assertEquals("value", message.getClaims().get("redirect_uri"));
    Assert.assertEquals("openid", message.getClaims().get("scope"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailMissingOpenidScopeParameter() throws InvalidClaimException {
    claims.put("scope", "profile");
    message = new AuthenticationRequest(claims);
    message.verify();
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testSuccessOfflineAccess() throws InvalidClaimException {
    claims.put("scope", "openid offline_access");
    claims.put("prompt", "consent");
    message = new AuthenticationRequest(claims);
    message.verify();
    Assert.assertEquals("consent", ((List<String>) message.getClaims().get("prompt")).get(0));
    Assert.assertEquals("openid offline_access", message.getClaims().get("scope"));
  }

  @Test
  public void testSuccessResponseTypeIdToken() throws InvalidClaimException {
    claims.put("response_type", "id_token token");
    claims.put("nonce", "DFHGFG");
    message = new AuthenticationRequest(claims);
    message.verify();
    Assert.assertEquals("DFHGFG", (String) message.getClaims().get("nonce"));
    Assert.assertEquals("id_token token", message.getClaims().get("response_type"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailResponseTypeIdTokenMissingNonce() throws InvalidClaimException {
    claims.put("response_type", "id_token token");
    message = new AuthenticationRequest(claims);
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailOfflineAccessNoConsent() throws InvalidClaimException {
    claims.put("scope", "openid offline_access");
    message = new AuthenticationRequest(claims);
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureMissingResponseTypeMandatoryParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.remove("client_id");
    message = new AuthenticationRequest(claims);
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailInvalidPromptCombination() throws InvalidClaimException {
    List<String> prompt = new ArrayList<String>();
    prompt.add("none");
    prompt.add("consent");
    claims.put("prompt", prompt);
    message = new AuthenticationRequest(claims);
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailUnAllowedPromptValue() throws InvalidClaimException {
    claims.put("prompt", "notlisted");
    message = new AuthenticationRequest(claims);
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailUnAllowedDisplayValue() throws InvalidClaimException {
    claims.put("display", "notlisted");
    message = new AuthenticationRequest(claims);
    message.verify();
  }

  @Test
  public void testSuccessIdTokenHint() throws InvalidClaimException, IllegalArgumentException,
      ImportException, UnknownKeyType, ValueError, IOException {
    Map<String, Object> idTokenClaims = new HashMap<String, Object>();
    idTokenClaims.put("iss", "issuer");
    idTokenClaims.put("sub", "subject");
    idTokenClaims.put("aud", "clientid");
    long now = System.currentTimeMillis() / 1000;
    idTokenClaims.put("exp", now + 60);
    idTokenClaims.put("iat", now);
    IDToken idTokenHint = new IDToken(idTokenClaims);
    idTokenHint.verify();
    List<Key> keysSign = getKeyJarPrv().getSigningKey(KeyType.RSA.name(), keyOwner, null, null);
    claims.put("id_token_hint", idTokenHint.toJwt(keysSign.get(0), "RS256"));
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
    IDToken idTokenHintFromJwt = new IDToken();
    idTokenHintFromJwt.fromJwt((String) req.getClaims().get("id_token_hint"), getKeyJarPub(),
        keyOwner);
    Assert.assertEquals((String) idTokenHintFromJwt.getClaims().get("iss"),
        (String) idTokenHint.getClaims().get("iss"));
  }


  @Test(expected = Exception.class)
  public void testFailIdTokenHintInvalid() throws InvalidClaimException {
    String idToken = "notparsableasidtoken";
    claims.put("id_token_hint", idToken);
    message = new AuthenticationRequest(claims);
    message.verify();
  }

}