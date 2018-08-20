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
import java.util.HashMap;
import java.util.Map;

import org.oidc.msg.ParameterVerification;

/**
 * An authorization error response message.
 */
public class AuthorizationErrorResponse extends ResponseMessage {
  
  { // Set parameter requirements for message.
    paramVerDefs.put("state", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    
    allowedValues.put("error", Arrays.asList("invalid_request",
        "unauthorized_client",
        "access_denied",
        "unsupported_response_type",
        "invalid_scope", "server_error",
        "temporarily_unavailable"));
  }
  
  /**
   * Constructor.
   */
  public AuthorizationErrorResponse() {
    this(new HashMap<String, Object>());
  }

  /**
   * Constructor.
   * @param claims The message parameters.
   */
  public AuthorizationErrorResponse(Map<String, Object> claims) {
    super(claims);
  }

}
