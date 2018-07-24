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

package org.oidc.msg.oauth2;

import java.util.HashMap;
import java.util.Map;

import org.oidc.msg.AbstractMessage;
import org.oidc.msg.ParameterVerification;

/**
 * The base OAuth2 response message containing optional error parameters.
 */
public class ResponseMessage extends AbstractMessage {

  { // Set parameter requirements for message.
    paramVerDefs.put("error", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("error_description", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("error_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
  }

  public ResponseMessage() {
    this(new HashMap<String, Object>());
  }

  public ResponseMessage(Map<String, Object> claims) {
    super(claims);
  }
}
