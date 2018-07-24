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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.oidc.msg.AbstractMessage;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.ParameterVerification;

public class RegistrationRequest extends AbstractMessage {

  public static final String DEFAULT_ENC_VALUE = "A128CBC-HS256";

  { // Set parameter requirements for message.
    paramVerDefs.put("redirect_uris", ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("response_types", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("grant_types", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("application_type", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("contacts", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("client_name", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("logo_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("client_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("policy_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("tos_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("jwks", ParameterVerification.SINGLE_OPTIONAL_MAP.getValue());
    paramVerDefs.put("jwks_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("sector_identifier_uri",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("subject_type", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("id_token_signed_response_alg",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("id_token_encrypted_response_alg",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("id_token_encrypted_response_enc",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("userinfo_signed_response_alg",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("userinfo_encrypted_response_alg",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("userinfo_encrypted_response_enc",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("request_object_signing_alg",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("request_object_encryption_alg",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("request_object_encryption_enc",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("token_endpoint_auth_method",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("token_endpoint_auth_signing_alg",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("default_max_age", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    paramVerDefs.put("require_auth_time", ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    paramVerDefs.put("default_acr_values",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("initiate_login_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("request_uris", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("post_logout_redirect_uris",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());

    defaultValues.put("application_type", "web");
    defaultValues.put("response_types", Arrays.asList("code"));

    allowedValues.put("application_type", Arrays.asList("native", "web"));
    allowedValues.put("subject_type", Arrays.asList("public", "pairwise"));
  }

  public RegistrationRequest() {
    this(new HashMap<String, Object>());
  }

  public RegistrationRequest(Map<String, Object> claims) {
    super(claims);
    addDefaultValues();
  }

  @Override
  public boolean verify() throws InvalidClaimException {
    boolean verify = false;
    try {
      verify = super.verify();
    } catch (InvalidClaimException e) {
      // carry on, possibly populate more error messages
    }

    if (getClaims().containsKey("initiate_login_uri")) {
      String uri = (String) getClaims().get("initiate_login_uri");
      if (uri.startsWith("https:")) {
        error.getMessages().add("'initiate_login_uri' has an invalid scheme");
      }
    }
    List<String> prefixes = Arrays.asList("request_object_encryption",
        "id_token_encrypted_response", "userinfo_encrypted_response");
    for (String prefix : prefixes) {
      String algParam = prefix + "_alg";
      String encParam = prefix + "_enc";
      if (getClaims().containsKey(algParam)) {
        if (!getClaims().containsKey(encParam)) {
          addClaim(encParam, DEFAULT_ENC_VALUE);
        }
      }
      if (getClaims().containsKey(encParam) && !getClaims().containsKey(algParam)) {
        error.getMessages().add("Required parameter '" + algParam + "' is missing");
      }
    }

    if (getClaims().containsKey("token_endpoint_auth_signing_alg")) {
      if ("none".equalsIgnoreCase((String) getClaims().get("token_endpoint_auth_signing_alg"))) {
        error.getMessages().add("'none' is not allowed for 'token_endpoint_auth_signing_alg'");
      }
    }

    if (error.getMessages().size() > 0) {
      throw new InvalidClaimException(
          "Message parameter verification failed. See Error object for details");
    }

    return verify;
  }
}