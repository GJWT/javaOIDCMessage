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

import org.oidc.msg.ErrorDetails;
import org.oidc.msg.ErrorType;

/**
 * Class implementing Request Object as in
 * http://openid.net/specs/openid-connect-core-1_0.html#RequestObject .
 */
public class RequestObject extends AuthenticationRequest {

  /**
   * Constructor.
   */
  public RequestObject() {
    this(new HashMap<String, Object>());
  }

  /**
   * Constructor.
   * 
   * @param claims
   *          Authentication request parameters as with {@link AuthenticationRequest} except
   *          redirect and redirect_uri are not allowed.
   */
  public RequestObject(Map<String, Object> claims) {
    super(claims);
  }

  /** {@inheritDoc} */
  @Override
  protected void doVerify() {
    if (getClaims().containsKey("request")) {
      getError().getDetails().add(new ErrorDetails("request", ErrorType.VALUE_NOT_ALLOWED,
          "request parameter not allowed"));
    }
    if (getClaims().containsKey("request_uri")) {
      getError().getDetails().add(new ErrorDetails("request_uri", ErrorType.VALUE_NOT_ALLOWED,
          "request_uri parameter not allowed"));
    }
  }

}