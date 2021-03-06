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
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.oauth2.AuthorizationRequest;

/**
 * Unit tests for {@link AuthorizationRequest}.
 */
public class AuthorizationRequestTest extends BaseMessageTest<AuthorizationRequest> {

  @Before
  public void setup() {
    message = new AuthorizationRequest();
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {

    Map<String, Object> claims = new HashMap<String, Object>();
    String[] responseType = new String[2];
    responseType[0] = "id_token";
    responseType[1] = "token";
    claims.put("response_type", responseType);
    claims.put("client_id", "value");
    message = new AuthorizationRequest(claims);
    Assert.assertTrue(message.verify());
    Assert.assertEquals("id_token token", message.getClaims().get("response_type"));
    Assert.assertEquals("value", message.getClaims().get("client_id"));
  }

  @Test
  public void testFailureMissingResponseTypeMandatoryParameter() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("client_id", "value");
    message = new AuthorizationRequest(claims);
    Assert.assertFalse(message.verify());
  }

  @Test
  public void testFailureMissingClientIdMandatoryParameter() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    List<String> responseType = new ArrayList<String>();
    responseType.add("code");
    claims.put("response_type", responseType);
    message = new AuthorizationRequest(claims);
    Assert.assertFalse(message.verify());
  }

}