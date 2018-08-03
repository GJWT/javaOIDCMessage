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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link ROPCAccessTokenRequest}.
 */
public class ROPCAccessTokenRequestTest extends BaseMessageTest<ROPCAccessTokenRequest> {

  @Before
  public void setup() {
    message = new ROPCAccessTokenRequest();
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    message.addClaim("grant_type", "mockGrantType");
    message.verify();
    Assert.assertEquals("mockGrantType", message.getClaims().get("grant_type"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureGrantTypeMissingMandatoryParameter() throws InvalidClaimException {
    message.verify();
  }

}
