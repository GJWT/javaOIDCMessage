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
import org.oidc.msg.InvalidClaimException;

public class IDTokenTest {

  Map<String, Object> claims = new HashMap<String, Object>();
  long now;

  /**
   * Setuo mandatory claims.
   */
  @Before
  public void setup() {
    now = System.currentTimeMillis() / 1000;
    claims.clear();
    claims.put("iss", "issuer");
    claims.put("sub", "subject");
    claims.put("aud", "clientid");
    claims.put("exp", now + 10);
    claims.put("iat", now);
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    IDToken req = new IDToken(claims);
    req.verify();
    Assert.assertEquals("issuer", req.getClaims().get("iss"));
    Assert.assertEquals("subject", req.getClaims().get("sub"));
    Assert.assertTrue(((List<String>) req.getClaims().get("aud")).contains("clientid"));
    Assert.assertEquals(now + 10, req.getClaims().get("exp"));
    Assert.assertEquals(now, req.getClaims().get("iat"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailMissingMandatoryParameter() throws InvalidClaimException {
    claims.remove("iss");
    IDToken req = new IDToken(claims);
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testWrongIssuer() throws InvalidClaimException {
    IDToken req = new IDToken(claims);
    req.setIssuer("other_issuer");
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testWrongClientId() throws InvalidClaimException {
    IDToken req = new IDToken(claims);
    req.setClientId("other_clientid");
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testMissingAzp() throws InvalidClaimException {
    List<String> aud = new ArrayList<String>();
    aud.add("clientid");
    aud.add("other_clientid");
    claims.put("aud", aud);
    IDToken req = new IDToken(claims);
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailAzpExistsNotMatchingAud() throws InvalidClaimException {
    List<String> aud = new ArrayList<String>();
    aud.add("clientid");
    aud.add("other_clientid");
    claims.put("aud", aud);
    claims.put("azp", "notmatching");
    IDToken req = new IDToken(claims);
    req.verify();
  }

  @Test
  public void testSuccessAzpExistsMatchingAud() throws InvalidClaimException {
    List<String> aud = new ArrayList<String>();
    aud.add("clientid");
    aud.add("other_clientid");
    claims.put("aud", aud);
    claims.put("azp", "other_clientid");
    IDToken req = new IDToken(claims);
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailAzpExistsNotMatchingClientId() throws InvalidClaimException {
    List<String> aud = new ArrayList<String>();
    aud.add("clientid");
    aud.add("other_clientid");
    claims.put("aud", aud);
    claims.put("azp", "other_clientid");
    IDToken req = new IDToken(claims);
    req.setClientId("third_clientId");
    req.verify();
  }

  @Test
  public void testSuccessAzpExistsMatchingClientId() throws InvalidClaimException {
    List<String> aud = new ArrayList<String>();
    aud.add("clientid");
    aud.add("other_clientid");
    claims.put("aud", aud);
    claims.put("azp", "other_clientid");
    IDToken req = new IDToken(claims);
    req.setClientId("other_clientid");
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailExp() throws InvalidClaimException {
    claims.put("exp", now - 1);
    IDToken req = new IDToken(claims);
    req.verify();
  }

  @Test
  public void testSuccessExpSkew() throws InvalidClaimException {
    claims.put("exp", now - 1);
    IDToken req = new IDToken(claims);
    req.setSkew(2);
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailIat() throws InvalidClaimException {
    claims.put("iat", now - 100);
    IDToken req = new IDToken(claims);
    req.setStorageTime(90);
    req.verify();
  }

  @Test
  public void testSuccessIat() throws InvalidClaimException {
    claims.put("iat", now - 100);
    IDToken req = new IDToken(claims);
    req.setStorageTime(110);
    req.verify();
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testFailNonceVerification() throws InvalidClaimException {
    claims.put("nonce", "nonce1");
    IDToken req = new IDToken(claims);
    req.setNonce("nonce2");
    req.verify();
  }
  
  @Test
  public void testSuccessNonceVerification() throws InvalidClaimException {
    claims.put("nonce", "nonce");
    IDToken req = new IDToken(claims);
    req.setNonce("nonce");
    req.verify();
  }

}