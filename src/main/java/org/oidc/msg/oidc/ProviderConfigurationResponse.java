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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.ParameterVerification;

public class ProviderConfigurationResponse extends org.oidc.msg.oauth2.ASConfigurationResponse {

  { // Remove requirements from OAuth2 ASConfigurationResponse
    paramVerDefs.clear();
    // Set parameter requirements for message.
    paramVerDefs.put("issuer", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("authorization_endpoint",
        ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("token_endpoint", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("userinfo_endpoint", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("jwks_uri", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("registration_endpoint",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("scopes_supported", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("response_types_supported",
        ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("response_modes_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("grant_types_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("acr_values_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("subject_types_supported",
        ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("id_token_signing_alg_values_supported",
        ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("id_token_encryption_alg_values_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("id_token_encryption_enc_values_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("userinfo_signing_alg_values_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("userinfo_encryption_alg_values_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("userinfo_encryption_enc_values_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("request_object_signing_alg_values_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("request_object_encryption_alg_values_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("request_object_encryption_enc_values_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("token_endpoint_auth_methods_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("token_endpoint_auth_signing_alg_values_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("display_values_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("claim_types_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("claims_supported", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("service_documentation",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("claims_locales_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("ui_locales_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("claims_parameter_supported",
        ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    paramVerDefs.put("request_parameter_supported",
        ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    paramVerDefs.put("request_uri_parameter_supported",
        ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    paramVerDefs.put("require_request_uri_registration",
        ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    paramVerDefs.put("op_policy_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("op_tos_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("check_session_iframe",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("end_session_endpoint",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());

    defaultValues.put("version", "3.0");
    defaultValues.put("token_endpoint_auth_methods_supported",
        Arrays.asList("client_secret_basic"));
    defaultValues.put("claims_parameter_supported", Boolean.FALSE);
    defaultValues.put("request_parameter_supported", Boolean.FALSE);
    defaultValues.put("request_uri_parameter_supported", Boolean.TRUE);
    defaultValues.put("require_request_uri_registration", Boolean.TRUE);
    defaultValues.put("grant_types_supported", Arrays.asList("authorization_code", "implicit"));
  }

  public ProviderConfigurationResponse() {
    this(new HashMap<String, Object>());
  }

  public ProviderConfigurationResponse(Map<String, Object> claims) {
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
    if (getClaims().containsKey("scopes_supported")) {
      @SuppressWarnings("unchecked")
      List<String> scopes = (List<String>) getClaims().get("scopes_supported");
      if (!scopes.contains("openid")) {
        error.getMessages()
            .add("Parameter 'scopes_supported' does not contain expected value 'openid'");
      }
    }
    try {
      URI uri = new URI((String) getClaims().get("issuer"));
      if (!"https".equals(uri.getScheme()) || uri.getQuery() != null || uri.getFragment() != null) {
        error.getMessages().add("Parameter 'issuer' has an invalid value");
      }
    } catch (URISyntaxException e) {
      error.getMessages().add("Parameter 'issuer' is not a valid URL");
    }
    @SuppressWarnings("unchecked")
    List<String> rts = (List<String>) getClaims().get("response_types_supported");
    for (String rt : rts) {
      if (Pattern.compile("\\bcode\\b").matcher(rt).find()) {
        if (!getClaims().containsKey("token_endpoint")) {
          error.getMessages()
              .add("'token_endpoint' is required when code response_type is supported");
        }
      }
    }

    if (error.getMessages().size() > 0) {
      throw new InvalidClaimException(
          "Message parameter verification failed. See Error object for details");
    }

    return verify;
  }
}