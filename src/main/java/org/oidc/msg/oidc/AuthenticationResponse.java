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

import com.auth0.jwt.JWT;
import com.auth0.msg.KeyJar;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.ParameterVerification;
import org.oidc.msg.oauth2.AuthorizationResponse;
import org.oidc.msg.oidc.util.TokenHash;

/**
 * Authentication Response message as described in
 * http://openid.net/specs/openid-connect-core-1_0.html#AuthResponse,
 * http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse or
 * http://openid.net/specs/openid-connect-core-1_0.html#HybridAuthResponse.
 */
public class AuthenticationResponse extends AuthorizationResponse {

  /** Key Jar for performing keys performing JWT verification. */
  private KeyJar keyJar;
  /** Owner of the verification key in the Key Jar. */
  private String keyOwner;

  {
    paramVerDefs.put("access_token", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("token_type", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("expires_in", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    paramVerDefs.put("scope", ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("state", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("code", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("id_token", ParameterVerification.SINGLE_OPTIONAL_JWT.getValue());
    // TODO: For some reason this parameter is included in python implementation and checked
    // against client id. Check the reason.
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
   * Set Key Jar for JWT verification keys. If not set verification is not done.
   * 
   * @param keyJar
   *          Key Jar for JWT verification keys.
   */
  public void setKeyJar(KeyJar keyJar) {
    this.keyJar = keyJar;
  }

  /**
   * Set Owner of the JWT verification keys in Key Jar.
   * 
   * @param keyOwner
   *          Owner of the JWT verification keys in Key Jar.
   */
  public void setKeyOwner(String keyOwner) {
    this.keyOwner = keyOwner;
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

    if (getClaims().get("aud") != null && getClientId() != null) {
      List<String> aud = (List<String>) getClaims().get("aud");
      if (!aud.contains(getClientId())) {
        getError().getMessages().add("Client ID not included in audience");
      }
    }

    // TODO: Still missing passing options for:
    // 'encalg', 'encenc', 'sigalg','issuer', 'allow_missing_kid', 'no_kid_issuer','trusting',
    // 'skew', 'nonce_storage_time', 'client_id'.
    // Python implementation passes some of them to fromJwt and some to verify in map structures.
    //

    if (getClaims().get("id_token") != null) {
      IDToken idToken = new IDToken();
      try {
        idToken.fromJwt((String) getClaims().get("id_token"), keyJar, keyOwner);
        idToken.verify();
      } catch (IOException e) {
        getError().getMessages().add("Unable to verify id token signature");
      }

      if (getClaims().get("access_token") != null) {
        if (idToken.getClaims().get("at_hash") == null) {
          getError().getMessages().add("at_hash must be in id token if returned with access token");
        } else {
          String atHash = TokenHash.compute((String) getClaims().get("access_token"),
              JWT.decode((String) getClaims().get("id_token")).getAlgorithm());
          if (!((String) idToken.getClaims().get("at_hash")).equals(atHash)) {
            getError().getMessages()
                .add(String.format("at_hash in id token not same as expected value '%s'", atHash));
          }
        }
      }
      if (getClaims().get("code") != null) {
        if (idToken.getClaims().get("c_hash") == null) {
          getError().getMessages()
              .add("c_hash must be in id token if returned with authorization code");
        } else {
          String codeHash = TokenHash.compute((String) getClaims().get("code"),
              JWT.decode((String) getClaims().get("id_token")).getAlgorithm());
          if (!((String) idToken.getClaims().get("c_hash")).equals(codeHash)) {
            getError().getMessages()
                .add(String.format("c_hash in id token not same as expected value '%s'", codeHash));
          }
        }
      }
    }

    if (getError().getMessages().size() > 0) {
      this.setVerified(false);
      throw new InvalidClaimException(
          "Message parameter verification failed. See Error object for details");
    }
    return hasError();
  }

}
