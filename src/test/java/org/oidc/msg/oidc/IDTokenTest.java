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
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;

public class IDTokenTest extends BaseMessageTest<IDToken> {

  Map<String, Object> claims = new HashMap<String, Object>();
  long now;

  /**
   * Setuo mandatory claims.
   */
  @Before
  public void setup() {
    message = new IDToken();
    now = System.currentTimeMillis()/1000;
    claims.clear();
    claims.put("iss", "issuer");
    claims.put("sub", "subject");
    claims.put("aud", "clientid");
    claims.put("exp", now+5);
    claims.put("iat", now);
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    message = new IDToken(claims);
    message.verify();
    Assert.assertEquals("issuer", message.getClaims().get("iss"));
    Assert.assertEquals("subject", message.getClaims().get("sub"));
    Assert.assertTrue(((List<String>) message.getClaims().get("aud")).contains("clientid"));
    Assert.assertEquals((now + 5)*1000, ((Date)message.getClaims().get("exp")).getTime());
    Assert.assertEquals(now*1000, ((Date)message.getClaims().get("iat")).getTime());
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailMissingMandatoryParameter() throws InvalidClaimException {
    claims.remove("iss");
    message = new IDToken(claims);
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testWrongIssuer() throws InvalidClaimException {
    message = new IDToken(claims);
    message.setIssuer("other_issuer");
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testWrongClientId() throws InvalidClaimException {
    message = new IDToken(claims);
    message.setClientId("other_clientid");
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testMissingAzp() throws InvalidClaimException {
    List<String> aud = new ArrayList<String>();
    aud.add("clientid");
    aud.add("other_clientid");
    claims.put("aud", aud);
    message = new IDToken(claims);
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailAzpExistsNotMatchingAud() throws InvalidClaimException {
    List<String> aud = new ArrayList<String>();
    aud.add("clientid");
    aud.add("other_clientid");
    claims.put("aud", aud);
    claims.put("azp", "notmatching");
    message = new IDToken(claims);
    message.verify();
  }

  @Test
  public void testSuccessAzpExistsMatchingAud() throws InvalidClaimException {
    List<String> aud = new ArrayList<String>();
    aud.add("clientid");
    aud.add("other_clientid");
    claims.put("aud", aud);
    claims.put("azp", "other_clientid");
    message = new IDToken(claims);
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailAzpExistsNotMatchingClientId() throws InvalidClaimException {
    List<String> aud = new ArrayList<String>();
    aud.add("clientid");
    aud.add("other_clientid");
    claims.put("aud", aud);
    claims.put("azp", "other_clientid");
    message = new IDToken(claims);
    message.setClientId("third_clientId");
    message.verify();
  }

  @Test
  public void testSuccessAzpExistsMatchingClientId() throws InvalidClaimException {
    List<String> aud = new ArrayList<String>();
    aud.add("clientid");
    aud.add("other_clientid");
    claims.put("aud", aud);
    claims.put("azp", "other_clientid");
    message = new IDToken(claims);
    message.setClientId("other_clientid");
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailExp() throws InvalidClaimException {
    claims.put("exp", now - 5);
    message = new IDToken(claims);
    message.verify();
  }

  @Test
  public void testSuccessExpSkew() throws InvalidClaimException {
    claims.put("exp", now - 1);
    message = new IDToken(claims);
    message.setSkew(5);
    message.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailIat() throws InvalidClaimException {
    claims.put("iat", now - 10);
    message = new IDToken(claims);
    message.setStorageTime(5);
    message.verify();
  }

  @Test
  public void testSuccessIat() throws InvalidClaimException {
    claims.put("iat", now - 100);
    message = new IDToken(claims);
    message.setStorageTime(110);
    message.verify();
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testFailNonceVerification() throws InvalidClaimException {
    claims.put("nonce", "nonce1");
    message = new IDToken(claims);
    message.setNonce("nonce2");
    message.verify();
  }
  
  @Test
  public void testSuccessNonceVerification() throws InvalidClaimException {
    claims.put("nonce", "nonce");
    message = new IDToken(claims);
    message.setNonce("nonce");
    message.verify();
  }

}