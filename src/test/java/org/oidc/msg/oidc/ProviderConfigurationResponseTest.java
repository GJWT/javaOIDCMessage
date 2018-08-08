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

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;

/**
 * Unit tests for {@link ProviderConfigurationResponse}.
 */
public class ProviderConfigurationResponseTest
    extends BaseMessageTest<ProviderConfigurationResponse> {

  @Before
  public void setup() {
    message = new ProviderConfigurationResponse();
    addRequiredClaims();
  }

  protected void addRequiredClaims() {
    message.addClaim("issuer", "https://example.org");
    message.addClaim("authorization_endpoint", "https://example.org/authorize");
    message.addClaim("jwks_uri", "https://example.org/keyset.jwk");
    message.addClaim("response_types_supported", Arrays.asList("id_token"));
    message.addClaim("subject_types_supported", Arrays.asList("public"));
    message.addClaim("id_token_signing_alg_values_supported", Arrays.asList("RS256"));
  }

  @Test
  public void testInvalidScopesSupported() {
    message.addClaim("scopes_supported", "info");
    Assert.assertFalse(message.verify());
    Assert.assertEquals(1, message.getError().getDetails().size());
    Assert.assertEquals("scopes_supported",
        message.getError().getDetails().get(0).getParameterName());
  }

  @Test
  public void testInvalidIssuerNonUri() {
    message.addClaim("issuer", "not_and_uri");
    Assert.assertFalse(message.verify());
    Assert.assertEquals(1, message.getError().getDetails().size());
    Assert.assertEquals("issuer", message.getError().getDetails().get(0).getParameterName());
  }

  @Test
  public void testInvalidIssuerInvalidUriScheme() {
    message.addClaim("issuer", "http://example.org");
    Assert.assertFalse(message.verify());
    Assert.assertEquals(1, message.getError().getDetails().size());
    Assert.assertEquals("issuer", message.getError().getDetails().get(0).getParameterName());
  }

  @Test
  public void testInvalidIssuerInvalidUriWithParameter() {
    message.addClaim("issuer", "https://example.org?query=test");
    Assert.assertFalse(message.verify());
    Assert.assertEquals(1, message.getError().getDetails().size());
    Assert.assertEquals("issuer", message.getError().getDetails().get(0).getParameterName());
  }

  @Test
  public void testInvalidIssuerInvalidUriWithFragment() {
    message.addClaim("issuer", "https://example.org#mockFragment");
    Assert.assertFalse(message.verify());
    Assert.assertEquals(1, message.getError().getDetails().size());
    Assert.assertEquals("issuer", message.getError().getDetails().get(0).getParameterName());
  }

  @Test
  public void testMissingTokenEndpoint() {
    message.addClaim("response_types_supported", "code");
    Assert.assertFalse(message.verify());
    Assert.assertEquals(1, message.getError().getDetails().size());
    Assert.assertEquals("token_endpoint",
        message.getError().getDetails().get(0).getParameterName());
  }

  @Test
  public void testValidTokenEndpoint() {
    message.addClaim("response_types_supported", "code");
    message.addClaim("token_endpoint", "https://example.org/token");
    Assert.assertTrue(message.verify());
  }

  @Test
  public void testValidMinimal() {
    Assert.assertTrue(message.verify());
  }

}
