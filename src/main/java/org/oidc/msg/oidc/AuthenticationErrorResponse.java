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

import org.apache.commons.collections.ListUtils;
import org.oidc.msg.oauth2.AuthorizationErrorResponse;

public class AuthenticationErrorResponse extends AuthorizationErrorResponse {

  {
    allowedValues.put("error", ListUtils.union(allowedValues.get("error"),
        Arrays.asList("interaction_required", "login_required", "session_selection_required",
            "consent_required", "invalid_request_uri", "invalid_request_object",
            "registration_not_supported", "request_not_supported", "request_uri_not_supported")));
  }

  public AuthenticationErrorResponse() {
    this(new HashMap<String, Object>());
  }

  public AuthenticationErrorResponse(Map<String, Object> claims) {
    super(claims);
  }

}
