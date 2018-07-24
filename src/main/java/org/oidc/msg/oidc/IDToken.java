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

/** ID Token as in http://openid.net/specs/openid-connect-core-1_0.html#IDToken. */
public class IDToken extends OpenIDSchema {

  /**
   * TODO functionality: Missing to_jwt related functionality like adding c_hash, jti etc. These are
   * OP features.
   */

  /** Issuer to match the id token to. */
  private String issuer;

  /** Client ID to match the id token to. */
  private String clientId;

  /** Nonce to match the id token to. */
  private String nonce;

  /** Skew in seconds for calculating if the id token has expired or not. */
  private long skew = 0;

  /** Nonce storage time in seconds. */
  private long storageTime = 4 * 3600;

  {
    // Updating parameter requirements.
    paramVerDefs.put("iss", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("sub", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("aud", ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("exp", ParameterVerification.SINGLE_REQUIRED_INT.getValue());
    paramVerDefs.put("iat", ParameterVerification.SINGLE_REQUIRED_INT.getValue());
    paramVerDefs.put("auth_time", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    paramVerDefs.put("nonce", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("at_hash", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("c_hash", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("acr", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("amr", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("azp", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("sub_jwk", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());

  }

  /**
   * Constructor.
   */
  public IDToken() {
    this(new HashMap<String, Object>());
  }

  /**
   * Constructor.
   * 
   * @param claims
   *          ID Token claims as described in
   *          http://openid.net/specs/openid-connect-core-1_0.html#IDToken.
   */
  public IDToken(Map<String, Object> claims) {
    super(claims);
  }

  /**
   * Set Issuer to use when verifying id token.
   * 
   * @param issuer
   *          Issuer to match the id token to.
   */
  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  /**
   * Set Client ID to use when verifying id token.
   * 
   * @param clientId
   *          Client ID to match the id token to.
   */
  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  /**
   * Set Nonce to use when verifying id token. Comparison is done only if id token has nonce.
   * 
   * @param nonce
   *          Nonce to match the id token to.
   */
  public void setNonce(String nonce) {
    this.nonce = nonce;
  }

  /**
   * Set Skew in seconds for calculating if the id token has expired or not.
   * 
   * @param skew
   *          Skew in seconds for calculating if the id token has expired or not.
   */
  public void setSkew(long skew) {
    this.skew = skew;
  }

  /**
   * Set nonce storage time in seconds. Id token must not have been issued longer ago than nonce
   * storage time is. Default is 4h.
   * 
   * @param storageTime
   *          nonce storage time in seconds
   */
  public void setStorageTime(long storageTime) {
    this.storageTime = storageTime;
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

    if (issuer != null && !issuer.equals(getClaims().get("iss"))) {
      getError().getMessages()
          .add(String.format(
              "Issuer mismatch, expected value '%s' for iss claim but got '%s' instead", issuer,
              getClaims().get("iss")));
    }

    if (clientId != null && !((List<String>) getClaims().get("aud")).contains(clientId)) {
      getError().getMessages()
          .add(String.format("Client ID '%s' is not listed in the aud claim", clientId));
    }

    if (((List<String>) getClaims().get("aud")).size() > 1 && (getClaims().get("azp") == null
        || !((List<String>) getClaims().get("aud")).contains(getClaims().get("azp")))) {
      getError().getMessages()
          .add("If claim aud has multiple values one of them must have value of azp claim.");
    }

    if (getClaims().get("azp") != null && clientId != null
        && !clientId.equals((String) getClaims().get("azp"))) {
      getError().getMessages().add(String.format(
          "Client ID '%s' should equal to azp claim value '%s'", clientId, getClaims().get("azp")));
    }

    long now = System.currentTimeMillis() / 1000;
    if (now - skew > (long) getClaims().get("exp")) {
      getError().getMessages().add("Claim exp is in the past");
    }

    if ((long) getClaims().get("iat") + storageTime < now - skew) {
      getError().getMessages().add("id token has been issued too long ago");
    }

    if (nonce != null && getClaims().get("nonce") != null
        && !nonce.equals(getClaims().get("nonce"))) {
      getError().getMessages().add("nonce mismatch");
    }

    if (getError().getMessages().size() > 0) {
      this.setVerified(false);
      throw new InvalidClaimException(
          "Message parameter verification failed. See Error object for details");
    }

    return hasError();

  }
}
