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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import org.oidc.msg.DeserializationException;
import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;
import org.oidc.msg.ParameterVerification;
import org.oidc.msg.oauth2.AuthorizationRequest;

/**
 * Authentication request message as described in
 * http://openid.net/specs/openid-connect-core-1_0.html.
 */
public class AuthenticationRequest extends AuthorizationRequest {

  /** Key Jar for performing keys performing JWT verification. */
  private KeyJar keyJar;
  /** Owner of the verification key in the Key Jar. */
  private String keyOwner;

  {
    // Updating parameter requirements.
    paramVerDefs.put("redirect_uri", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("scope", ParameterVerification.REQUIRED_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("redirect_uri", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("nonce", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("display", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("prompt", ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("max_age", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    paramVerDefs.put("claims", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("ui_locales",
        ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("claims_locales",
        ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("id_token_hint", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("login_hint", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("acr_values",
        ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("request", ParameterVerification.SINGLE_OPTIONAL_JWT.getValue());
    paramVerDefs.put("request_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("response_mode", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    // Updating allowed values of parameters
    allowedValues.put("display", Arrays.asList("page", "popup", "touch", "wap"));
    allowedValues.put("prompt", Arrays.asList("none", "login", "consent", "select_account"));
  }

  /**
   * Constructor.
   */
  public AuthenticationRequest() {
    this(new HashMap<String, Object>());
  }

  /**
   * Constructor.
   * 
   * @param claims
   *          Authentication request parameters. Expected claims are response_type(REQUIRED),
   *          client_id(REQUIRED), redirect_uri(REQUIRED), scope (REQUIRED), nonce
   *          (OPTIONAL/REQUIRED), state(RECOMMENDED) and other claims described in
   *          http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
   */
  public AuthenticationRequest(Map<String, Object> claims) {
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
    String request = ((String) getClaims().get("request"));
    if (request != null) {
      RequestObject requestObject = new RequestObject();
      try {
        requestObject.fromJwt(request, keyJar, keyOwner);
        if (!requestObject.verify()) {
          for (ErrorDetails requestErrorDetails : requestObject.getError().getDetails()) {
            ErrorDetails details = new ErrorDetails("request", requestErrorDetails.getErrorType(),
                requestErrorDetails.getErrorMessage(), requestErrorDetails.getErrorCause());
            getError().getDetails().add(details);
          }
        }
      } catch (DeserializationException | JWTDecodeException e) {
        ErrorDetails details = new ErrorDetails("request", ErrorType.INVALID_VALUE_FORMAT,
            String.format("Unable to parse request object from '%s'", request));
        error.getDetails().add(details);
      }
    }

    // TODO: Missing from Rolands version the case ''Nonce in id_token not matching nonce in authz'

    String idTokenHint = ((String) getClaims().get("id_token_hint"));
    if (idTokenHint != null) {
      IDToken idToken = new IDToken();
      try {
        idToken.fromJwt(idTokenHint, keyJar, keyOwner);
        if (!idToken.verify()) {
          for (ErrorDetails idTokenErrorDetails : idToken.getError().getDetails()) {
            ErrorDetails details = new ErrorDetails("id_token_hint",
                idTokenErrorDetails.getErrorType(), idTokenErrorDetails.getErrorMessage(),
                idTokenErrorDetails.getErrorCause());
            getError().getDetails().add(details);
          }
        }
      } catch (DeserializationException | JWTDecodeException e) {
        ErrorDetails details = new ErrorDetails("id_token_hint", ErrorType.INVALID_VALUE_FORMAT,
            String.format("Unable to parse id_token_hint from '%s'", idTokenHint));
        error.getDetails().add(details);
      }
    }

    String spaceSeparatedScopes = ((String) getClaims().get("scope"));
    if (spaceSeparatedScopes == null
        || !Pattern.compile("\\bopenid\\b").matcher(spaceSeparatedScopes).find()) {
      getError().getDetails().add(new ErrorDetails("scope", ErrorType.VALUE_NOT_ALLOWED,
          "Parameter scope must exist and contain value openid"));
    }

    String responseType = (String) getClaims().get("response_type");
    if (responseType != null && (Pattern.compile("\\bid_token\\b").matcher(responseType).find()
        && (getClaims().get("nonce") == null || ((String) getClaims().get("nonce")).isEmpty()))) {
      getError().getDetails().add(new ErrorDetails("nonce", ErrorType.MISSING_REQUIRED_VALUE,
          "Nonce is mandatory if response type contains id_token"));
    }

    String spaceSeparatedPrompts = ((String) getClaims().get("prompt"));
    if (spaceSeparatedPrompts != null
        && Pattern.compile("\\bnone\\b").matcher(spaceSeparatedPrompts).find()
        && spaceSeparatedPrompts.split(" ").length > 1) {
      getError().getDetails().add(new ErrorDetails("prompt", ErrorType.MISSING_REQUIRED_VALUE,
          "Prompt value none must not be used with other values"));
    }

    if (spaceSeparatedScopes != null
        && Pattern.compile("\\boffline_access\\b").matcher(spaceSeparatedScopes).find()) {
      if (spaceSeparatedPrompts == null
          || !Pattern.compile("\\bconsent\\b").matcher(spaceSeparatedPrompts).find()) {
        getError().getDetails().add(new ErrorDetails("prompt", ErrorType.MISSING_REQUIRED_VALUE,
            "When offline_access scope is used prompt must have value consent"));
      }
    }
  }

}