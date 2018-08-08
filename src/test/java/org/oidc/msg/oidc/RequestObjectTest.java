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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.BaseMessageTest;

/**
 * Unit tests for {@link RequestObject}.
 */
public class RequestObjectTest extends BaseMessageTest<RequestObject> {

  @Before
  public void setup() {
    message = new RequestObject();
    message.addClaim("response_type", "code");
    message.addClaim("client_id", "value");
    message.addClaim("redirect_uri", "value");
    message.addClaim("scope", "openid");
  }

  @Test
  public void testRequestIncluded() {
    message.addClaim("request", "mockRequest");
    Assert.assertFalse(message.verify());
    Assert.assertEquals(1, message.getError().getDetails().size());
    Assert.assertEquals("request", message.getError().getDetails().get(0).getParameterName());
  }

  @Test
  public void testRequestUriIncluded() {
    message.addClaim("request_uri", "mockRequestUri");
    Assert.assertFalse(message.verify());
    Assert.assertEquals(1, message.getError().getDetails().size());
    Assert.assertEquals("request_uri", message.getError().getDetails().get(0).getParameterName());
  }
}
