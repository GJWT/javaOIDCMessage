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

package org.oidc.msg.oauth2;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.oauth2.AuthorizationRequest;

public class AuthorizationRequestTest {

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {

    Map<String, Object> claims = new HashMap<String, Object>();
    String[] responseType = new String[2];
    responseType[0] = "id_token";
    responseType[1] = "token";
    claims.put("response_type", responseType);
    claims.put("client_id", "value");
    AuthorizationRequest req = new AuthorizationRequest(claims);
    req.verify();
    Assert.assertEquals("id_token token", req.getClaims().get("response_type"));
    Assert.assertEquals("value", req.getClaims().get("client_id"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureMissingResponseTypeMandatoryParameter() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("client_id", "value");
    AuthorizationRequest req = new AuthorizationRequest(claims);
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureMissingClientIdMandatoryParameter() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    List<String> responseType = new ArrayList<String>();
    responseType.add("code");
    claims.put("response_type", responseType);
    AuthorizationRequest req = new AuthorizationRequest(claims);
    req.verify();
  }

}