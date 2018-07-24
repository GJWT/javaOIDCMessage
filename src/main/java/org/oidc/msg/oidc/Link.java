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

import java.util.HashMap;
import java.util.Map;

import org.oidc.msg.AbstractMessage;
import org.oidc.msg.ParameterVerification;

/**
 * One of the attributes of JSON Resource Description (JRD) Contains these attributes: rel, type,
 * href, titles, and properties For more info, please see:
 * https://tools.ietf.org/html/rfc7033#section-4.4.4
 */
public class Link extends AbstractMessage {

  { // Set parameter requirements for message.
    paramVerDefs.put("rel", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("type", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("href", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("titles", ParameterVerification.SINGLE_OPTIONAL_MAP.getValue());
    paramVerDefs.put("properties", ParameterVerification.SINGLE_OPTIONAL_MAP.getValue());
  }

  public Link() {
    this(new HashMap<String, Object>());
  }

  public Link(Map<String, Object> claims) {
    super(claims);
  }
}
