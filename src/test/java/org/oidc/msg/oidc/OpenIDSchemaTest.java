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
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.InvalidClaimException;

/**
 * Unit tests for {@link OpenIDSchema}.
 */
public class OpenIDSchemaTest extends BaseMessageTest<OpenIDSchema> {

  Map<String, Object> claims = new HashMap<String, Object>();

  /**
   * Setuo mandatory claims.
   */
  @Before
  public void setup() {
    message = new OpenIDSchema();
    claims.clear();
    claims.put("sub", "foo");
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    message = new OpenIDSchema(claims);
    Assert.assertTrue(message.verify());
    Assert.assertEquals("foo", message.getClaims().get("sub"));
  }

  @Test
  public void testFailMissingOpenidScopeParameter() throws InvalidClaimException {
    claims.remove("sub");
    message = new OpenIDSchema(claims);
    Assert.assertFalse(message.verify());
  }

  @Test
  public void testSuccessDateFormats() throws InvalidClaimException {
    message = new OpenIDSchema(claims);
    claims.put("birthdate", "1990-12-31");
    Assert.assertTrue(message.verify());
    claims.put("birthdate", "0000-12-31");
    Assert.assertTrue(message.verify());
    claims.put("birthdate", "1990");
    Assert.assertTrue(message.verify());
  }

  @Test
  public void testFailDateFormats() throws InvalidClaimException {
    claims.put("birthdate", "X-1555-15");
    message = new OpenIDSchema(claims);
    Assert.assertFalse(message.verify());
  }

  @Test
  public void testFailNullValue() throws InvalidClaimException {
    claims.put("any", null);
    message = new OpenIDSchema(claims);
    Assert.assertFalse(message.verify());
  }

}