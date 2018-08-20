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

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.msg.KeyJar;

import java.util.HashMap;
import java.util.Map;

import org.oidc.msg.DeserializationException;
import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;
import org.oidc.msg.ParameterVerification;

/**
 * An OIDC access token response message.
 */
public class AccessTokenResponse extends org.oidc.msg.oauth2.AccessTokenResponse {
  
  /** Key Jar for performing keys performing JWT verification. */
  private KeyJar keyJar;
  /** Owner of the verification key in the Key Jar. */
  private String keyOwner;

  
  { // Set parameter requirements for message.
    paramVerDefs.put("id_token", ParameterVerification.SINGLE_OPTIONAL_JWT.getValue());
  }
  
  /**
   * Constructor.
   */
  public AccessTokenResponse() {
    this(new HashMap<String, Object>());
  }
  
  /**
   * Constructor.
   * @param claims The message parameters.
   */
  public AccessTokenResponse(Map<String, Object> claims) {
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
  
  /** {@inheritDoc} */
  @Override
  protected void doVerify() {
    if (getClaims().containsKey("id_token")) {
      IDToken idToken = new IDToken();
      try {
        idToken.fromJwt((String) getClaims().get("id_token"), keyJar, keyOwner);
        if (!idToken.verify()) {
          for (ErrorDetails idTokenErrorDetails : idToken.getError().getDetails()) {
            ErrorDetails details = new ErrorDetails("id_token", idTokenErrorDetails.getErrorType(),
                idTokenErrorDetails.getErrorMessage(), idTokenErrorDetails.getErrorCause());
            getError().getDetails().add(details);
          }
        }
      } catch (DeserializationException | JWTDecodeException e) {
        getError().getDetails().add(new ErrorDetails("id_token", ErrorType.INVALID_VALUE_FORMAT,
            "Unable to verify id token signature", e));
      }  
    }
  }
}
