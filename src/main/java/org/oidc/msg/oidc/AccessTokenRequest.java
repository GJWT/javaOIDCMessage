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

import org.oidc.msg.ParameterVerification;

public class AccessTokenRequest extends org.oidc.msg.oauth2.AccessTokenRequest {

  { // Set parameter requirements for message.
    paramVerDefs.put("client_assertion_type",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("client_assertion", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());

    allowedValues.put("client_assertion_type",
        Arrays.asList("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
  }

  public AccessTokenRequest() {
    this(new HashMap<String, Object>());
  }

  public AccessTokenRequest(Map<String, Object> claims) {
    super(claims);
    addDefaultValues();
  }

}
