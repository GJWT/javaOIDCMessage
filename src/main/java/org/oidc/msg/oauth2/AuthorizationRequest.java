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

import java.util.HashMap;
import java.util.Map;

import org.oidc.msg.AbstractMessage;
import org.oidc.msg.ParameterVerification;

/**
 * Authorization Request message as described in https://tools.ietf.org/html/rfc6749 for
 * Authorization Code Grant https://tools.ietf.org/html/rfc6749#section-4.1 and Implicit Grant
 * https://tools.ietf.org/html/rfc6749#section-4.2.
 */
public class AuthorizationRequest extends AbstractMessage {

  { // Set parameter requirements for message.
    paramVerDefs.put("response_type",
        ParameterVerification.REQUIRED_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("client_id", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("redirect_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("scope", ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("state", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
  }

  /**
   * Constructor.
   */
  public AuthorizationRequest() {
    this(new HashMap<String, Object>());
  }
  
  /**
   * Constructor.
   * 
   * @param claims
   *          Authorization request claims. Expected claims are response_type(REQUIRED),
   *          client_id(REQUIRED), redirect_uri(OPTIONAL), scope (OPTIONAL) and state(RECOMMENDED).
   */
  public AuthorizationRequest(Map<String, Object> claims) {
    super(claims);
  }
}