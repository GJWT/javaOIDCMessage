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
import java.util.HashMap;
import java.util.Map;
import org.oidc.msg.oauth2.ResponseMessage;

/**
 * A user info error response message.
 */
public class UserInfoErrorResponse extends ResponseMessage {

  {
    allowedValues.put("error",
        Arrays.asList("invalid_schema", "invalid_request", "invalid_token", "insufficient_scope"));
  }

  /**
   * Constructor.
   */
  public UserInfoErrorResponse() {
    this(new HashMap<String, Object>());
  }

  /**
   * Constructor.
   * 
   * @param claims
   *          Error parameters as described in
   *          http://openid.net/specs/openid-connect-core-1_0.html#UserInfoError.
   */
  public UserInfoErrorResponse(Map<String, Object> claims) {
    super(claims);
  }

}
