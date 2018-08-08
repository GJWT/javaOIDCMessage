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
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link RegistrationRequest}.
 */
public class RegistrationRequestTest extends BaseMessageTest<RegistrationRequest> {

  private List<String> redirectUris;

  @Before
  public void setup() {
    message = new RegistrationRequest();
    redirectUris = Arrays.asList("https://example.org/cb");
    message.addClaim("redirect_uris", redirectUris);
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    Assert.assertTrue(message.verify());
    Assert.assertEquals(redirectUris, message.getClaims().get("redirect_uris"));
  }

  @Test
  public void testInvalidInitiateLoginUri() throws InvalidClaimException {
    message.addClaim("initiate_login_uri", "http://example.org/initiate");
    Assert.assertFalse(message.verify());
    Assert.assertEquals(1, message.getError().getDetails().size());
    Assert.assertEquals("initiate_login_uri",
        message.getError().getDetails().get(0).getParameterName());

  }

  @Test
  public void testInvalidTokenEndpointAuthSigningAlg() throws InvalidClaimException {
    message.addClaim("token_endpoint_auth_signing_alg", "none");
    Assert.assertFalse(message.verify());
    Assert.assertEquals(1, message.getError().getDetails().size());
    Assert.assertEquals("token_endpoint_auth_signing_alg",
        message.getError().getDetails().get(0).getParameterName());
  }

  @Test
  public void testMissingRequestObjectEncryptionAlg() {
    testMissingEncryptionAlg("request_object_encryption");
  }

  @Test
  public void testMissingIdTokenEncryptionAlg() {
    testMissingEncryptionAlg("id_token_encrypted_response");
  }

  @Test
  public void testMissingUserinfoEncryptionAlg() {
    testMissingEncryptionAlg("userinfo_encrypted_response");
  }

  @Test
  public void testDefaultRequestObjectEncryptionEnc() {
    testDefaultEncryptionEnc("request_object_encryption");
  }

  @Test
  public void testDefaultIdTokenEncryptionEnc() {
    testDefaultEncryptionEnc("id_token_encrypted_response");
  }

  @Test
  public void testDefaultUserinfoEncryptionEnc() {
    testDefaultEncryptionEnc("userinfo_encrypted_response");
  }

  protected void testMissingEncryptionAlg(String prefix) {
    message.addClaim(prefix + "_enc", "mockEnc");
    Assert.assertFalse(message.verify());
    Assert.assertEquals(1, message.getError().getDetails().size());
    Assert.assertEquals(prefix + "_alg", message.getError().getDetails().get(0).getParameterName());
  }

  protected void testDefaultEncryptionEnc(String prefix) {
    message.addClaim(prefix + "_alg", "mockAlg");
    Assert.assertTrue(message.verify());
    Assert.assertEquals(RegistrationRequest.DEFAULT_ENC_VALUE,
        message.getClaims().get(prefix + "_enc"));
  }

}
