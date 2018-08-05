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

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.ParameterVerification;
import org.oidc.msg.oauth2.AuthorizationRequest;

/**
 * Authentication request message as described in
 * http://openid.net/specs/openid-connect-core-1_0.html.
 */
public class AuthenticationRequest extends AuthorizationRequest {

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

    String request = ((String) getClaims().get("request"));
    if (request != null) {
      RequestObject requestObject = new RequestObject();
      try {
        // TODO: set keyjar and owner
        requestObject.fromJwt(request, null, null);
      } catch (IOException e) {
        getError().getMessages()
            .add(String.format("Unable to parse request object from '%s'", request));
      }
      try {
        requestObject.verify();
      } catch (InvalidClaimException e) {
        for (String errorDesc : requestObject.getError().getMessages()) {
          getError().getMessages()
              .add(String.format("request parameter verification failed: '%s'", errorDesc));
        }
      }
    }

    // TODO: verify from Rolands code the case ''Nonce in id_token not matching nonce in authz'
    String idTokenHint = ((String) getClaims().get("id_token_hint"));
    if (idTokenHint != null) {
      IDToken idToken = new IDToken();
      try {
        // TODO: set keyjar and owner
        idToken.fromJwt(idTokenHint, null, null);
      } catch (IOException e) {
        getError().getMessages()
            .add(String.format("Unable to parse id_token_hint from '%s'", idTokenHint));
      }
      try {
        idToken.verify();
      } catch (InvalidClaimException e) {
        for (String errorDesc : idToken.getError().getMessages()) {
          getError().getMessages()
              .add(String.format("id_token_hint parameter verification failed: '%s'", errorDesc));
        }
      }
    }

    String spaceSeparatedScopes = ((String) getClaims().get("scope"));
    if (spaceSeparatedScopes == null
        || !Pattern.compile("\\bopenid\\b").matcher(spaceSeparatedScopes).find()) {
      getError().getMessages().add("Parameter scope must exist and contain value openid");
    }

    String responseType = (String) getClaims().get("response_type");
    if (Pattern.compile("\\bid_token\\b").matcher(responseType).find()
        && (getClaims().get("nonce") == null || ((String) getClaims().get("nonce")).isEmpty())) {
      getError().getMessages().add("Nonce is mandatory if response type contains id_token");
    }

    String spaceSeparatedPrompts = ((String) getClaims().get("prompt"));
    if (spaceSeparatedPrompts != null
        && Pattern.compile("\\bnone\\b").matcher(spaceSeparatedPrompts).find()
        && spaceSeparatedPrompts.split(" ").length > 1) {
      getError().getMessages().add("Prompt value none must not be used with other values");
    }

    if (Pattern.compile("\\boffline_access\\b").matcher(spaceSeparatedScopes).find()) {
      if (spaceSeparatedPrompts == null
          || !Pattern.compile("\\bconsent\\b").matcher(spaceSeparatedPrompts).find()) {
        getError().getMessages()
            .add("When offline_access scope is used prompt must have value consent");
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