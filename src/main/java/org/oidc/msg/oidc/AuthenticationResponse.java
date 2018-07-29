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
import java.util.List;
import java.util.Map;

import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.ParameterVerification;
import org.oidc.msg.oauth2.AuthorizationResponse;

/**
 * Authentication Response message as described in
 * http://openid.net/specs/openid-connect-core-1_0.html#AuthResponse,
 * http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse or
 * http://openid.net/specs/openid-connect-core-1_0.html#HybridAuthResponse.
 */
public class AuthenticationResponse extends AuthorizationResponse {

  {
    paramVerDefs.put("access_token", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("token_type", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("expires_in", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    paramVerDefs.put("scope", ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("state", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("code", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("id_token", ParameterVerification.SINGLE_OPTIONAL_IDTOKEN.getValue());
    // TODO: For some reason this parameter is included in python implementation and checked
    // against client id.
    paramVerDefs.put("aud", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
  }

  /**
   * Constructor.
   */
  public AuthenticationResponse() {
    this(new HashMap<String, Object>());
  }

  /**
   * Constructor.
   * 
   * @param claims
   *          that form the response as detailed in
   *          http://openid.net/specs/openid-connect-core-1_0.html#AuthResponse,
   *          http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse,
   *          http://openid.net/specs/openid-connect-core-1_0.html#HybridAuthResponse or a error
   *          response for the used flow.
   */
  public AuthenticationResponse(Map<String, Object> claims) {
    super(claims);
  }

  /**
   * Verifies the presence of required message parameters. Verifies the the format of message
   * parameters.
   * 
   * @return true if parameters are successfully verified.
   * @throws InvalidClaimException
   *           if verification fails.
   */
  @SuppressWarnings("unchecked")
  public boolean verify() throws InvalidClaimException {
    super.verify();

    // TODO: For some reason aud parameter is included in python implementation as optional
    // parameter and checked against client id.
    if (getClaims().get("aud") != null && getClientId() != null) {
      List<String> aud = (List<String>) getClaims().get("aud");
      if (!aud.contains(getClientId())) {
        getError().getMessages().add(String.format("Client ID not included in audience"));
      }
    }
    
    // TODO: if id_token exists, pass arguments for it and perform verify: 'keyjar','verify',
    // 'encalg', 'encenc', 'sigalg','issuer', 'allow_missing_kid', 'no_kid_issuer','trusting',
    // 'skew', 'nonce_storage_time', 'client_id'

    // TODO: Check the algorithm for id token header.
    // If access token is returned, check from id token that at_hash exists and is correct one
    // If code is returned, check from id token that c_hash exists and is correct one

    if (getError().getMessages().size() > 0) {
      this.setVerified(false);
      throw new InvalidClaimException(
          "Message parameter verification failed. See Error object for details");
    }
    return hasError();
  }

}
