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

import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link WebfingerRequest}.
 */
public class WebfingerRequestTest {

  @Test
  public void testDefaultRelParameter() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("resource", "value");
    WebfingerRequest req = new WebfingerRequest();
    req.addClaim("resource", "value");
    req.verify();
    Map<String, Object> msgClaims = req.getClaims();
    Assert.assertEquals("value", msgClaims.get("resource"));
    Assert.assertEquals("http://openid.net/specs/connect/1.0/issuer", msgClaims.get("rel"));
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("resource", "value");
    claims.put("rel", "relValue");
    WebfingerRequest req = new WebfingerRequest(claims);
    req.verify();
    Map<String, Object> msgClaims = req.getClaims();
    Assert.assertEquals("value", msgClaims.get("resource"));
    Assert.assertEquals("relValue", msgClaims.get("rel"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureMissingResponseTypeMandatoryParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("custom", "value");
    WebfingerRequest req = new WebfingerRequest(claims);
    req.verify();
  }

}
