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
import java.util.List;
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
  /** Skew in seconds for calculating if the id token has expired or not. */
  private long skew = 0;
  /** Whether to allow missing kid when searching jwt key for signing. */
  private boolean allowMissingKid;
  /** Nonce storage time in seconds. */
  private Long storageTime;
  /** map of allowed kids for issuer. */
  private Map<String, List<String>> noKidIssuers;
  /** Whether to trust jku header. */
  private boolean trustJku;
  /** the allowed id token encryption key transport algorithm. */
  private String encAlg;
  /** the allowed id token encryption algorithm. */
  private String encEnc;
  /** the allowed id token signing algorithm. */
  private String sigAlg;
  /** Issuer to match the response to. */
  private String issuer;
  /** Client ID to match the response to. */
  private String clientId;
  /** Verified id token.*/
  private IDToken verifiedIdToken;

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
   * 
   * @param claims
   *          The message parameters.
   */
  public AccessTokenResponse(Map<String, Object> claims) {
    super(claims);
  }
  
  /**
   * Get verified id token.
   * @return verified id token
   */
  public IDToken getVerifiedIdToken() {
    return verifiedIdToken;
  }

  /**
   * Set the allowed id token encryption key transport algorithm.
   * 
   * @param encAlg
   *          the allowed id token encryption key transport algorithm
   */
  public void setEncAlg(String encAlg) {
    this.encAlg = encAlg;
  }

  /**
   * Set the allowed id token encryption algorithm.
   * 
   * @param encEnc
   *          the allowed id token encryption algorithm
   */
  public void setEncEnc(String encEnc) {
    this.encEnc = encEnc;
  }

  /**
   * Set the allowed id token signing algorithm.
   * 
   * @param sigAlg
   *          the allowed id token signing algorithm
   */
  public void setSigAlg(String sigAlg) {
    this.sigAlg = sigAlg;
  }

  /**
   * Set map of allowed kids for issuer.
   * 
   * @param noKidIssuers
   *          map of allowed kids for issuer
   */
  public void setNoKidIssuers(Map<String, List<String>> noKidIssuers) {
    this.noKidIssuers = noKidIssuers;
  }

  /**
   * Set whether to trust jku header.
   * 
   * @param trustJku
   *          whether to trust jku header
   */
  public void setTrustJku(boolean trustJku) {
    this.trustJku = trustJku;
  }

  /**
   * Set whether to allow missing kid when searching jwt key for signing.
   * 
   * @param allowMissingKid
   *          Whether to allow missing kid when searching jwt key for signing.
   */
  public void setAllowMissingKid(boolean allowMissingKid) {
    this.allowMissingKid = allowMissingKid;
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

  /** {@inheritDoc} */
  @Override
  protected void doVerify() {
    if (getClaims().containsKey("id_token")) {
      IDToken idToken = new IDToken();
      idToken.setClientId(clientId);
      idToken.setIssuer(issuer);
      idToken.setSkew(skew);
      if (storageTime != null) {
        idToken.setStorageTime(storageTime);
      }
      try {
        idToken.fromJwt((String) getClaims().get("id_token"), keyJar, issuer, noKidIssuers,
            allowMissingKid, trustJku, encAlg, encEnc, sigAlg);
        if (!idToken.verify()) {
          for (ErrorDetails idTokenErrorDetails : idToken.getError().getDetails()) {
            ErrorDetails details = new ErrorDetails("id_token", idTokenErrorDetails.getErrorType(),
                "Cause: (" + idTokenErrorDetails.toString() + ")", 
                idTokenErrorDetails.getErrorCause());
            getError().getDetails().add(details);
          }
        }
        verifiedIdToken = idToken;
      } catch (JWTDecodeException e) {
        getError().getDetails().add(new ErrorDetails("id_token", ErrorType.INVALID_VALUE_FORMAT,
            "Unable to verify id token signature", e));
      }
    }
  }
}
