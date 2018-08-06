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

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.UnknownKeyType;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.msg.Key;
import com.auth0.msg.KeyType;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.SerializationException;

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
    Assert.assertTrue(message.verify());
    Assert.assertEquals("code", message.getClaims().get("response_type"));
    Assert.assertEquals("value", message.getClaims().get("client_id"));
    Assert.assertEquals("value", message.getClaims().get("redirect_uri"));
    Assert.assertEquals("openid", message.getClaims().get("scope"));
  }

  @Test
  public void testFailMissingOpenidScopeParameter() throws InvalidClaimException {
    claims.put("scope", "profile");
    message = new AuthenticationRequest(claims);
    Assert.assertFalse(message.verify());
  }

  @Test
  public void testSuccessOfflineAccess() throws InvalidClaimException {
    claims.put("scope", "openid offline_access");
    claims.put("prompt", "consent");
    message = new AuthenticationRequest(claims);
    Assert.assertTrue(message.verify());
    Assert.assertEquals("consent",  message.getClaims().get("prompt"));
    Assert.assertEquals("openid offline_access", message.getClaims().get("scope"));
  }

  @Test
  public void testSuccessResponseTypeIdToken() throws InvalidClaimException {
    claims.put("response_type", "id_token token");
    claims.put("nonce", "DFHGFG");
    message = new AuthenticationRequest(claims);
    Assert.assertTrue(message.verify());
    Assert.assertEquals("DFHGFG", (String) message.getClaims().get("nonce"));
    Assert.assertEquals("id_token token", message.getClaims().get("response_type"));
  }

  @Test
  public void testFailResponseTypeIdTokenMissingNonce() throws InvalidClaimException {
    claims.put("response_type", "id_token token");
    message = new AuthenticationRequest(claims);
    Assert.assertFalse(message.verify());
  }

  @Test
  public void testFailOfflineAccessNoConsent() throws InvalidClaimException {
    claims.put("scope", "openid offline_access");
    message = new AuthenticationRequest(claims);
    Assert.assertFalse(message.verify());
  }

  @Test
  public void testFailureMissingResponseTypeMandatoryParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.remove("client_id");
    message = new AuthenticationRequest(claims);
    Assert.assertFalse(message.verify());
  }

  @Test
  public void testFailInvalidPromptCombination() throws InvalidClaimException {
    List<String> prompt = new ArrayList<String>();
    prompt.add("none");
    prompt.add("consent");
    claims.put("prompt", prompt);
    message = new AuthenticationRequest(claims);
    Assert.assertFalse(message.verify());
  }

  @Test
  public void testFailUnAllowedPromptValue() throws InvalidClaimException {
    claims.put("prompt", "notlisted");
    message = new AuthenticationRequest(claims);
    Assert.assertFalse(message.verify());
  }

  @Test
  public void testFailUnAllowedDisplayValue() throws InvalidClaimException {
    claims.put("display", "notlisted");
    message = new AuthenticationRequest(claims);
    Assert.assertFalse(message.verify());
  }

  @Test
  public void testSuccessIdTokenHint() throws InvalidClaimException, IllegalArgumentException,
      ImportException, UnknownKeyType, ValueError, IOException {
    IDToken idTokenHint = getIDTokenHint();
    List<Key> keysSign = getKeyJarPrv().getSigningKey(KeyType.RSA.name(), keyOwner, null, null);
    claims.put("id_token_hint", idTokenHint.toJwt(keysSign.get(0), "RS256"));
    AuthenticationRequest req = new AuthenticationRequest(claims);
    Assert.assertTrue(req.verify());
    IDToken idTokenHintFromJwt = new IDToken();
    idTokenHintFromJwt.fromJwt((String) req.getClaims().get("id_token_hint"), getKeyJarPub(),
        keyOwner);
    Assert.assertEquals((String) idTokenHintFromJwt.getClaims().get("iss"),
        (String) idTokenHint.getClaims().get("iss"));
  }

  @Test(expected = JWTDecodeException.class)
  public void testFailIdTokenHintInvalid() throws InvalidClaimException {
    String idToken = "notparsableasidtoken";
    claims.put("id_token_hint", idToken);
    message = new AuthenticationRequest(claims);
    Assert.assertFalse(message.verify());
  }

  /**
   * Form complete authentication request, url encode and decode it, verify you have the same
   * content.
   */
  @Test
  public void testUrlEncodingSuccess()
      throws InvalidClaimException, IllegalArgumentException, ImportException, UnknownKeyType,
      ValueError, SerializationException, MalformedURLException, IOException {
    claims.clear();
    //Form complete message   
    claims.put("scope", "openid email profile");
    claims.put("response_type", "id_token token");
    claims.put("client_id", "CLIENT_ID_010101010");
    claims.put("redirect_uri", "https://example.com");
    claims.put("state", "STATE_ID_010101010");
    claims.put("response_mode", "query");
    claims.put("nonce", "NONCE_010101010");
    claims.put("display", "page");
    // TODO: Verify type of prompt, sp sepatated list or json array like audience.
    String[] prompt = new String[2];
    prompt[0] = "login";
    prompt[1] = "consent";
    claims.put("prompt", prompt);
    claims.put("max_age", 60);
    String[] locales = new String[3];
    locales[0] = "fr-CA";
    locales[1] = "fr";
    locales[2] = "en";
    claims.put("ui_locales", locales);
    IDToken idTokenHint = getIDTokenHint();
    List<Key> keysSign = getKeyJarPrv().getSigningKey(KeyType.RSA.name(), keyOwner, null, null);
    claims.put("id_token_hint", idTokenHint.toJwt(keysSign.get(0), "RS256"));
    claims.put("login_hint", "user_is_bob");
    String[] acrs = new String[2];
    acrs[0] = "1";
    acrs[1] = "2";
    claims.put("acr_values", acrs);
    ClaimsRequest claimsRequest = getClaimsRequest();
    claims.put("claims", claimsRequest.toJson());
    RequestObject requestObject = new RequestObject(claims);
    Assert.assertTrue(requestObject.verify());
    claims.put("request", requestObject.toJwt(keysSign.get(0), "RS256"));
    message = new AuthenticationRequest(claims);
    message.verify();
    AuthenticationRequest messageParsed = new AuthenticationRequest();
    //Parse authentication request from url encoded message
    messageParsed.fromUrlEncoded(message.toUrlEncoded());
    Assert.assertTrue(messageParsed.verify());
    //Verify the content is the same
    IDToken idTokenHintParsed = new IDToken();
    idTokenHintParsed.fromJwt((String) messageParsed.getClaims().get("id_token_hint"),
        getKeyJarPub(), keyOwner);
    Assert.assertTrue(idTokenHintParsed.verify());
    RequestObject requestObjectParsed = new RequestObject(claims);
    requestObjectParsed.fromJwt((String) messageParsed.getClaims().get("request"), getKeyJarPub(),
        keyOwner);
    Assert.assertTrue(requestObjectParsed.verify());
    ClaimsRequest claimsRequestParsed = new ClaimsRequest();
    claimsRequestParsed.fromJson((String) messageParsed.getClaims().get("claims"));
    Assert.assertEquals(claimsRequestParsed.toJson(), getClaimsRequest().toJson());
    Assert.assertEquals((String) message.getClaims().get("scope"),
        (String) messageParsed.getClaims().get("scope"));
    Assert.assertEquals((String) message.getClaims().get("response_type"),
        (String) messageParsed.getClaims().get("response_type"));
    Assert.assertEquals((String) message.getClaims().get("client_id"),
        (String) messageParsed.getClaims().get("client_id"));
    Assert.assertEquals((String) message.getClaims().get("redirect_uri"),
        (String) messageParsed.getClaims().get("redirect_uri"));
    Assert.assertEquals((String) message.getClaims().get("state"),
        (String) messageParsed.getClaims().get("state"));
    Assert.assertEquals((String) message.getClaims().get("response_mode"),
        (String) messageParsed.getClaims().get("response_mode"));
    Assert.assertEquals((String) message.getClaims().get("nonce"),
        (String) messageParsed.getClaims().get("nonce"));
    Assert.assertEquals((String) message.getClaims().get("display"),
        (String) messageParsed.getClaims().get("display"));
    Assert.assertEquals((String) message.getClaims().get("prompt"),
        (String) messageParsed.getClaims().get("prompt"));
    Assert.assertEquals((String) message.getClaims().get("ui_locales"),
        (String) messageParsed.getClaims().get("ui_locales"));
    Assert.assertEquals((String) message.getClaims().get("login_hint"),
        (String) messageParsed.getClaims().get("login_hint"));
    Assert.assertEquals((String) message.getClaims().get("acr_values"),
        (String) messageParsed.getClaims().get("acr_values"));
  }

  private IDToken getIDTokenHint() throws InvalidClaimException {
    Map<String, Object> idTokenClaims = new HashMap<String, Object>();
    idTokenClaims.put("iss", "issuer");
    idTokenClaims.put("sub", "subject");
    idTokenClaims.put("aud", "clientid");
    long now = System.currentTimeMillis() / 1000;
    idTokenClaims.put("exp", now + 60);
    idTokenClaims.put("iat", now);
    IDToken idTokenHint = new IDToken(idTokenClaims);
    idTokenHint.verify();
    return idTokenHint;
  }

}