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

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;
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
  private long storageTime = 4 * 60 * 10 * 1000;

  {
    // Updating parameter requirements.
    paramVerDefs.put("iss", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("sub", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("aud", ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("exp", ParameterVerification.SINGLE_REQUIRED_DATE.getValue());
    paramVerDefs.put("iat", ParameterVerification.SINGLE_REQUIRED_DATE.getValue());
    paramVerDefs.put("auth_time", ParameterVerification.SINGLE_OPTIONAL_DATE.getValue());
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
    this.skew = skew * 1000;
  }

  /**
   * Set nonce storage time in seconds. Id token must not have been issued longer ago than nonce
   * storage time is. Default is 4h.
   * 
   * @param storageTime
   *          nonce storage time in seconds
   */
  public void setStorageTime(long storageTime) {
    this.storageTime = storageTime * 1000;
  }

  /** {@inheritDoc} */
  @Override
  protected void doVerify() {
    if (issuer != null && !issuer.equals(getClaims().get("iss"))) {
      getError().getDetails()
          .add(new ErrorDetails("iss", ErrorType.VALUE_NOT_ALLOWED,
              String.format(
                  "Issuer mismatch, expected value '%s' for iss claim but got '%s' instead", issuer,
                  getClaims().get("iss"))));
    }

    List<String> aud = (List<String>) getClaims().get("aud");
    if (clientId != null && (aud == null || !aud.contains(clientId))) {
      getError().getDetails().add(new ErrorDetails("aud", ErrorType.MISSING_REQUIRED_VALUE,
          String.format("Client ID '%s' is not listed in the aud claim", clientId)));
    }

    if (aud != null && aud.size() > 1 && ((getClaims().get("azp") == null)
        || !aud.contains(getClaims().get("azp")))) {
      getError().getDetails().add(new ErrorDetails("azp", ErrorType.MISSING_REQUIRED_VALUE,
          "If claim aud has multiple values one of them must have value of azp claim."));
    }

    if (getClaims().get("azp") != null && clientId != null
        && !clientId.equals((String) getClaims().get("azp"))) {
      getError().getDetails()
          .add(new ErrorDetails("azp", ErrorType.VALUE_NOT_ALLOWED,
              String.format("Client ID '%s' should equal to azp claim value '%s'", clientId,
                  getClaims().get("azp"))));
    }

    long now = System.currentTimeMillis();
    if (getClaims().containsKey("exp")) {
      long exp = ((Date) getClaims().get("exp")).getTime();
      if (now - skew > exp) {
        getError().getDetails()
            .add(new ErrorDetails("exp", ErrorType.VALUE_NOT_ALLOWED, "Claim exp is in the past"));
      }
    }

    if (getClaims().containsKey("iat")) {
      long iat = ((Date) getClaims().get("iat")).getTime();
      if (iat + storageTime < now - skew) {
        getError().getDetails().add(new ErrorDetails("iat", ErrorType.VALUE_NOT_ALLOWED,
            "id token has been issued too long ago"));
      }
    }

    if (nonce != null && getClaims().get("nonce") != null
        && !nonce.equals(getClaims().get("nonce"))) {
      getError().getDetails()
          .add(new ErrorDetails("nonce", ErrorType.VALUE_NOT_ALLOWED, "nonce mismatch"));
    }
  }
}
