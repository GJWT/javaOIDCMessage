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
import java.util.Map;

import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.ParameterVerification;
import org.oidc.msg.oauth2.ResponseMessage;

/** Schema for claims presented in idtoken and userinfo response. */
public class OpenIDSchema extends ResponseMessage {

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
   * 
   * @param claims
   *          Claims for openid schema verification.
   */
  public OpenIDSchema(Map<String, Object> claims) {
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
  public boolean verify() throws InvalidClaimException {
    super.verify();
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
          getError().getMessages()
              .add(String.format("birthdate '%s' should be of YYYY-MM-DD or YYYY format.", date));
        }
      }
    }
    for (String key : getClaims().keySet()) {
      if (getClaims().get(key) == null) {
        getError().getMessages().add(String.format("Value of '%s' is null.", key));
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
