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
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.msg.KeyJar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.oidc.msg.DeserializationException;
import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;
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
  /** Verified id token. */
  private IDToken verifiedIdToken;

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
   *          http://openid.net/specs/openid-connect-core-1_0.html#HybridAuthResponse.
   */
  public AuthenticationResponse(Map<String, Object> claims) {
    super(claims);
  }

  /**
   * Get verified id token.
   * 
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

  /** {@inheritDoc} */
  @Override
  protected void doVerify() {
    if (getClaims().get("aud") != null && getClientId() != null) {
      @SuppressWarnings("unchecked")
      List<String> aud = (List<String>) getClaims().get("aud");
      if (!aud.contains(getClientId())) {
        getError().getDetails().add(new ErrorDetails("aud", ErrorType.MISSING_REQUIRED_VALUE,
            "Client ID not included in audience"));
      }
    }

    if (getClaims().get("id_token") != null) {
      IDToken idToken = new IDToken();
      idToken.setClientId(getClientId());
      idToken.setIssuer(getIssuer());
      idToken.setSkew(skew);
      if (storageTime != null) {
        idToken.setStorageTime(storageTime);
      }
      try {
        idToken.fromJwt((String) getClaims().get("id_token"), keyJar, getIssuer(), noKidIssuers,
            allowMissingKid, trustJku, encAlg, encEnc, sigAlg);
        if (!idToken.verify()) {
          for (ErrorDetails idTokenErrorDetails : idToken.getError().getDetails()) {
            ErrorDetails details = new ErrorDetails("id_token", idTokenErrorDetails.getErrorType(),
                idTokenErrorDetails.getErrorMessage(), idTokenErrorDetails.getErrorCause());
            getError().getDetails().add(details);
          }
        }
        verifiedIdToken = idToken;
      } catch (JWTDecodeException e) {
        getError().getDetails().add(new ErrorDetails("id_token", ErrorType.INVALID_VALUE_FORMAT,
            "Unable to verify id token signature", e));
      }

      if (getClaims().get("access_token") != null) {
        if (idToken.getClaims().get("at_hash") == null) {
          getError().getDetails().add(new ErrorDetails("at_hash", ErrorType.MISSING_REQUIRED_VALUE,
              "at_hash must be in id token if returned with access token"));
        } else {
          String atHash = TokenHash.compute((String) getClaims().get("access_token"),
              JWT.decode((String) getClaims().get("id_token")).getAlgorithm());
          if (!((String) idToken.getClaims().get("at_hash")).equals(atHash)) {
            getError().getDetails().add(new ErrorDetails("at_hash", ErrorType.VALUE_NOT_ALLOWED,
                String.format("at_hash in id token not same as expected value '%s'", atHash)));
          }
        }
      }
      if (getClaims().get("code") != null) {
        if (idToken.getClaims().get("c_hash") == null) {
          getError().getDetails().add(new ErrorDetails("c_hash", ErrorType.MISSING_REQUIRED_VALUE,
              "c_hash must be in id token if returned with authorization code"));
        } else {
          String codeHash = TokenHash.compute((String) getClaims().get("code"),
              JWT.decode((String) getClaims().get("id_token")).getAlgorithm());
          if (!((String) idToken.getClaims().get("c_hash")).equals(codeHash)) {
            getError().getDetails().add(new ErrorDetails("c_hash", ErrorType.VALUE_NOT_ALLOWED,
                String.format("c_hash in id token not same as expected value '%s'", codeHash)));
          }
        }
      }
    }
  }
}
