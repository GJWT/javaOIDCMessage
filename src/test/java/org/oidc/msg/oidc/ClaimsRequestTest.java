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
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.SerializationException;

/**
 * Unit tests for {@link ClaimsRequest}.
 */
public class ClaimsRequestTest extends BaseMessageTest<ClaimsRequest> {

  Map<String, Object> claims = new HashMap<String, Object>();
  
  @Before
  public void setup() {
    message = new ClaimsRequest();
  }

  /**
   * 
   * Tests producing fairly complex claims request
   * 
   */
  @Test
  public void testSuccessMandatoryParameters()
      throws InvalidClaimException, SerializationException {
    Map<String, Object> userInfoClaimsRequestMembers = new HashMap<String, Object>();
    Map<String, Object> essentialTrue = new HashMap<String, Object>();
    essentialTrue.put("essential", true);
    userInfoClaimsRequestMembers.put("given_name", essentialTrue);
    userInfoClaimsRequestMembers.put("nickname", null);
    userInfoClaimsRequestMembers.put("email", essentialTrue);
    userInfoClaimsRequestMembers.put("email_verified", essentialTrue);
    userInfoClaimsRequestMembers.put("picture", null);
    userInfoClaimsRequestMembers.put("http://example.info/claims/groups", null);
    claims.put("userinfo", userInfoClaimsRequestMembers);
    Map<String, Object> acrParams = new HashMap<String, Object>();
    acrParams.put("essential", true);
    List<String> acrValues = new ArrayList<String>();
    acrValues.add("urn:mace:incommon:iap:silver");
    acrValues.add("urn:mace:incommon:iap:bronze");
    acrParams.put("values", acrValues);
    Map<String, Object> idTokenClaimsRequestMembers = new HashMap<String, Object>();
    idTokenClaimsRequestMembers.put("acr", acrParams);
    Map<String, Object> value = new HashMap<String, Object>();
    value.put("value", "248289761001");
    idTokenClaimsRequestMembers.put("sub", value);
    idTokenClaimsRequestMembers.put("auth_time", essentialTrue);
    claims.put("idtoken", idTokenClaimsRequestMembers);
    message = new ClaimsRequest(claims);
    message.verify();
    Assert.assertThat(message.toJson(), CoreMatchers.is(
        "{\"idtoken\":{\"acr\":{\"values\":[\"urn:mace:incommon:iap:silver\",\"urn:mace:incommon:iap:bronze\"],\"essential\":true},\"sub\":{\"value\":\"248289761001\"},\"auth_time\":{\"essential\":true}},\"userinfo\":{\"email_verified\":{\"essential\":true},\"nickname\":null,\"http://example.info/claims/groups\":null,\"given_name\":{\"essential\":true},\"email\":{\"essential\":true},\"picture\":null}}"));
  }

}