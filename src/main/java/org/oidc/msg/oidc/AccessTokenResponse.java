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

import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.ParameterVerification;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

public class AccessTokenResponse extends org.oidc.msg.oauth2.AccessTokenResponse {
  
  { // Set parameter requirements for message.
    paramVerDefs.put("id_token", ParameterVerification.SINGLE_OPTIONAL_JWT.getValue());
  }
  
  public AccessTokenResponse() {
    this(new HashMap<String, Object>());
  }
  
  public AccessTokenResponse(Map<String, Object> claims) {
    super(claims);
  }
  
  public boolean verify() throws InvalidClaimException {
    boolean result = super.verify();
    if (getClaims().containsKey("id_token")) {
      DecodedJWT idToken = JWT.decode((String) getClaims().get("id_token"));
      //TODO: verify the signature & al.
    }
    return result;
  }
}
