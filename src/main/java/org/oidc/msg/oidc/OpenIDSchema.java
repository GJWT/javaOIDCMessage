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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.oidc.msg.CryptoMessage;
import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;
import org.oidc.msg.ParameterVerification;
import org.oidc.msg.oauth2.ResponseMessage;

import com.auth0.msg.KeyJar;

/** Schema for claims presented in idtoken and userinfo response. */
public class OpenIDSchema extends ResponseMessage implements CryptoMessage {

  /** Key Jar for performing keys performing JWT verification. */
  private KeyJar keyJar;
  /** Whether to allow missing kid when searching jwt key for signing. */
  private boolean allowMissingKid;
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
  /** the issuer of keys. */
  private String issuer;

  { // Set parameter requirements for message.
    paramVerDefs.put("error", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("sub", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("name", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("given_name", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("family_name", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("middle_name", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("nickname", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("preferred_username", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("profile", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("picture", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("website", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("email", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("email_verified", ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    paramVerDefs.put("gender", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("birthdate", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("zoneinfo", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("locale", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("phone_number", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("phone_number_verified",
        ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    // TODO:ADDRESS MESSAGE CLASS ?
    paramVerDefs.put("address", ParameterVerification.SINGLE_OPTIONAL_MESSAGE.getValue());
    paramVerDefs.put("updated_at", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    // TODO:CLAIM_NAMES MESSAGE CLASS ?
    paramVerDefs.put("_claim_names", ParameterVerification.SINGLE_OPTIONAL_MESSAGE.getValue());
    // TODO:CLAIM_SOURCES MESSAGE CLASS ?
    paramVerDefs.put("_claim_sources", ParameterVerification.SINGLE_OPTIONAL_MESSAGE.getValue());

  }

  /**
   * Constructor.
   */
  public OpenIDSchema() {
    this(new HashMap<String, Object>());
  }

  /**
   * Constructor.
   * 
   * @param claims
   *          Claims for openid schema verification.
   */
  public OpenIDSchema(Map<String, Object> claims) {
    super(claims);
  }

  /** {@inheritDoc} */
  @Override
  protected void doVerify() {
    String date = (String) getClaims().get("birthdate");
    if (date != null) {
      try {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        sdf.parse(date);
      } catch (ParseException e) {
        try {
          SimpleDateFormat sdf = new SimpleDateFormat("yyyy");
          sdf.parse(date);
        } catch (ParseException e1) {
          getError().getDetails().add(new ErrorDetails("birthdate", ErrorType.VALUE_NOT_ALLOWED,
              String.format("birthdate '%s' should be of YYYY-MM-DD or YYYY format.", date)));
        }
      }
    }
    for (String key : getClaims().keySet()) {
      if (getClaims().get(key) == null) {
        getError().getDetails().add(new ErrorDetails(key, ErrorType.VALUE_NOT_ALLOWED,
            String.format("Value of '%s' is null.", key)));
      }
    }
  }

  @Override
  public void setEncAlg(String encAlg) {
    this.encAlg = encAlg;

  }

  @Override
  public String getEncAlg() {
    return encAlg;
  }

  @Override
  public void setEncEnc(String encEnc) {
    this.encEnc = encEnc;

  }

  @Override
  public String getEncEnc() {
    return encEnc;
  }

  @Override
  public void setSigAlg(String sigAlg) {
    this.sigAlg = sigAlg;
  }

  @Override
  public String getSigAlg() {
    return sigAlg;
  }

  @Override
  public void setNoKidIssuers(Map<String, List<String>> noKidIssuers) {
    this.noKidIssuers = noKidIssuers;

  }

  @Override
  public Map<String, List<String>> getNoKidIssuers() {
    return noKidIssuers;
  }

  @Override
  public void setTrustJku(boolean trustJku) {
    this.trustJku = trustJku;

  }

  @Override
  public boolean getTrustJku() {
    return trustJku;
  }

  @Override
  public void setAllowMissingKid(boolean allowMissingKid) {
    this.allowMissingKid = allowMissingKid;

  }

  @Override
  public boolean getAllowMissingKid() {
    return allowMissingKid;
  }

  @Override
  public void setKeyJar(KeyJar keyJar) {
    this.keyJar = keyJar;

  }

  @Override
  public KeyJar getKeyJar() {
    return keyJar;
  }

  @Override
  public void setIssuer(String issuer) {
    this.issuer = issuer;

  }

  @Override
  public String getIssuer() {
    return issuer;
  }
}
