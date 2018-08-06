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

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link ASConfigurationResponse}.
 */
public class ASConfigurationResponseTest extends BaseMessageTest<ASConfigurationResponse> {

  @Before
  public void setup() {
    message = new ASConfigurationResponse();
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    message.addClaim("issuer", "mockIssuer");
    message.addClaim("response_types_supported", Arrays.asList("mockResponseType"));
    message.addClaim("grant_types_supported", Arrays.asList("mockGrantType"));
    Assert.assertTrue(message.verify());
    Assert.assertEquals("mockIssuer", message.getClaims().get("issuer"));
    Assert.assertEquals(Arrays.asList("mockResponseType"),
        message.getClaims().get("response_types_supported"));
    Assert.assertEquals(Arrays.asList("mockGrantType"),
        message.getClaims().get("grant_types_supported"));
  }

  @Test
  public void testFailureMissingIssuerMandatoryParameter() throws InvalidClaimException {
    message.addClaim("response_types_supported", Arrays.asList("mockResponseType"));
    message.addClaim("grant_types_supported", Arrays.asList("mockGrantType"));
    Assert.assertFalse(message.verify());
  }

  @Test
  public void testFailureMissingGrantTypesMandatoryParameter() throws InvalidClaimException {
    message.addClaim("issuer", "mockIssuer");
    message.addClaim("response_types_supported", Arrays.asList("mockResponseType"));
    Assert.assertFalse(message.verify());
  }

  @Test
  public void testFailureMissingResponseTypesMandatoryParameter() throws InvalidClaimException {
    message.addClaim("issuer", "mockIssuer");
    message.addClaim("grant_types_supported", Arrays.asList("mockGrantType"));
    Assert.assertFalse(message.verify());
  }
}
