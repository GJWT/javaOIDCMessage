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

import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;
import org.oidc.msg.ParameterVerification;

/**
 * Authorization Response message as described in https://tools.ietf.org/html/rfc6749 for
 * Authorization Code Grant https://tools.ietf.org/html/rfc6749#section-4.1.
 */
public class AuthorizationResponse extends ResponseMessage {

  {
    paramVerDefs.put("code", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("state", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("iss", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("client_id", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
  }

  /** Issuer to match the response to. */
  private String issuer;

  /** Client ID to match the response to. */
  private String clientId;

  /**
   * Constructor.
   */
  public AuthorizationResponse() {
    this(new HashMap<String, Object>());
  }

  /**
   * Constructor.
   * 
   * @param claims
   *          The message parameters.
   */
  public AuthorizationResponse(Map<String, Object> claims) {
    super(claims);
  }

  /**
   * Set Issuer to use when verifying response.
   * 
   * @param issuer
   *          Issuer to match the response to.
   */
  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  /**
   * Get Issuer to match the response to.
   * 
   * @return Issuer to match the response to
   */
  public String getIssuer() {
    return issuer;
  }

  /**
   * Set Client ID to use when verifying response.
   * 
   * @param clientId
   *          Client ID to match the response to.
   */
  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  /**
   * Get Client ID to use when verifying response.
   * 
   * @return Client ID to match the response to.
   */
  public String getClientId() {
    return clientId;
  }

  /** {@inheritDoc} */
  @Override
  protected void doVerify() {
    // TODO: If iss and client_id contents are checked on this level, why is state content not?
    if (getClaims().get("client_id") != null
        && !((String) getClaims().get("client_id")).equals(clientId)) {
      ErrorDetails details = new ErrorDetails("client_id", ErrorType.VALUE_NOT_ALLOWED,
          String.format("Response parameter client_id has value '%s' but expected value is '%s'",
              (String) getClaims().get("client_id"), clientId));
      error.getDetails().add(details);
    }
    if (getClaims().get("iss") != null && !((String) getClaims().get("iss")).equals(issuer)) {
      ErrorDetails details = new ErrorDetails("iss", ErrorType.VALUE_NOT_ALLOWED,
          String.format("Response parameter iss has value '%s' but expected value is '%s'",
              (String) getClaims().get("iss"), issuer));
      error.getDetails().add(details);
    }
  }
}
