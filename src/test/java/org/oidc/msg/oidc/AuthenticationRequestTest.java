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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;

public class AuthenticationRequestTest extends BaseMessageTest {

  Map<String, Object> claims = new HashMap<String, Object>();
  
  /**
   * Setup mandatory claims.
   */
  @Before
  public void setup() {
    claims.clear();
    claims.put("response_type", "code");
    claims.put("client_id", "value");
    claims.put("redirect_uri", "value");
    claims.put("scope", "openid");
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
    Assert.assertEquals("code", req.getClaims().get("response_type"));
    Assert.assertEquals("value", req.getClaims().get("client_id"));
    Assert.assertEquals("value", req.getClaims().get("redirect_uri"));
    Assert.assertEquals("openid", req.getClaims().get("scope"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailMissingOpenidScopeParameter() throws InvalidClaimException {
    claims.put("scope", "profile");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testSuccessOfflineAccess() throws InvalidClaimException {
    claims.put("scope", "openid offline_access");
    claims.put("prompt", "consent");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
    Assert.assertEquals("consent", ((List<String>) req.getClaims().get("prompt")).get(0));
    Assert.assertEquals("openid offline_access", req.getClaims().get("scope"));
  }

  @Test
  public void testSuccessResponseTypeIdToken() throws InvalidClaimException {
    claims.put("response_type", "id_token token");
    claims.put("nonce", "DFHGFG");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
    Assert.assertEquals("DFHGFG", (String) req.getClaims().get("nonce"));
    Assert.assertEquals("id_token token", req.getClaims().get("response_type"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailResponseTypeIdTokenMissingNonce() throws InvalidClaimException {
    claims.put("response_type", "id_token token");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailOfflineAccessNoConsent() throws InvalidClaimException {
    claims.put("scope", "openid offline_access");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureMissingResponseTypeMandatoryParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.remove("client_id");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailInvalidPromptCombination() throws InvalidClaimException {
    List<String> prompt = new ArrayList<String>();
    prompt.add("none");
    prompt.add("consent");
    claims.put("prompt", prompt);
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailUnAllowedPromptValue() throws InvalidClaimException {
    claims.put("prompt", "notlisted");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailUnAllowedDisplayValue() throws InvalidClaimException {
    claims.put("display", "notlisted");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
  }

  //@Test
  public void testSuccessIdTokenHint() throws InvalidClaimException {
    // TODO: Update test
    claims.put("id_token_hint", idToken);
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
    Assert.assertEquals(idToken, req.getClaims().get("id_token_hint"));
  }

  @Test(expected = Exception.class)
  public void testFailIdTokenHintInvalid() throws InvalidClaimException {
    String idToken = "notparsableasidtoken";
    claims.put("id_token_hint", idToken);
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
    Assert.assertEquals(idToken, req.getClaims().get("id_token_hint"));
  }

}