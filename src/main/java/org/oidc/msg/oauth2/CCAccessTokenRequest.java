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

import org.oidc.msg.AbstractMessage;
import org.oidc.msg.ParameterVerification;

/**
 * Client Credential grant flow access token request.
 */
public class CCAccessTokenRequest extends AbstractMessage {

  { // Set parameter requirements for message.
    paramVerDefs.put("grant_type", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("scope", ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    
    defaultValues.put("grant_type", "client_credentials");
    
    allowedValues.put("grant_type", Arrays.asList("client_credentials"));
  }
  
  /**
   * Constructor.
   */
  public CCAccessTokenRequest() {
    this(new HashMap<String, Object>());
  }
  
  /**
   * Constructor.
   * @param claims The message parameters.
   */
  public CCAccessTokenRequest(Map<String, Object> claims) {
    super(claims);
    addDefaultValues();
  }
}
