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
import org.oidc.msg.SerializationException;

public class AuthenticationResponseTest extends BaseMessageTest<AuthenticationResponse> {

  Map<String, Object> claims = new HashMap<String, Object>();

  /**
   * Setup mandatory claims.
   */
  @Before
  public void setup() {
    message = new AuthenticationResponse();
    claims.clear();
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testSuccessAudienceNoClientIdParameter() throws InvalidClaimException {
    List<String> aud = new ArrayList<String>();
    aud.add("client");
    claims.put("aud", aud);
    AuthenticationResponse resp = new AuthenticationResponse(claims);
    resp.verify();
    Assert.assertEquals("client", ((List<String>) resp.getClaims().get("aud")).get(0));
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testSuccessAudienceMatchingClientIdParameter() throws InvalidClaimException {
    List<String> aud = new ArrayList<String>();
    aud.add("client");
    claims.put("aud", aud);
    AuthenticationResponse resp = new AuthenticationResponse(claims);
    resp.setClientId("client");
    resp.verify();
    Assert.assertEquals("client", ((List<String>) resp.getClaims().get("aud")).get(0));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureAudienceNotMatchingClientIdParameter() throws InvalidClaimException {
    List<String> aud = new ArrayList<String>();
    aud.add("client");
    claims.put("aud", aud);
    AuthenticationResponse resp = new AuthenticationResponse(claims);
    resp.setClientId("client_not_matching");
    resp.verify();
  }

  @Test
  public void testSuccessValidIdToken() throws InvalidClaimException, IllegalArgumentException,
      ImportException, UnknownKeyType, ValueError, IOException, SerializationException {
    // Add id token to response as OP would propably add
    Key key = getKeyJarPrv().getSigningKey(KeyType.RSA.name(), keyOwner, null, null).get(0);
    String jwt = generateIdTokenNow(new HashMap<String, Object>(), key, "RS256");
    AuthenticationResponse resp = new AuthenticationResponse();
    resp.addClaim("id_token", jwt);
    resp.verify();
    // Now from RP point of view, parse the response and validate also the id token while validating
    // response
    AuthenticationResponse respParsed = new AuthenticationResponse();
    respParsed.fromUrlEncoded(resp.toUrlEncoded());
    respParsed.setKeyOwner(keyOwner);
    respParsed.setKeyJar(getKeyJarPub());
    respParsed.verify();
    // Second approach, validate id token after getting it from response
    respParsed.fromUrlEncoded(resp.toUrlEncoded());
    respParsed.verify();
    IDToken idToken = new IDToken();
    idToken.fromJwt((String) respParsed.getClaims().get("id_token"), getKeyJarPub(), keyOwner);
    idToken.verify();
    // Finally assert we really have the same jwt
    Assert.assertEquals(jwt, (String) respParsed.getClaims().get("id_token"));
  }

}