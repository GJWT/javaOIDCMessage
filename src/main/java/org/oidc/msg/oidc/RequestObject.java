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
import org.oidc.msg.InvalidClaimException;

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
    if (getClaims().containsKey("redirect")) {
      getError().getMessages().add("redirect parameter not allowed");
    }
    if (getClaims().containsKey("redirect_uri")) {
      getError().getMessages().add("redirect_uri parameter not allowed");
    }
    if (getError().getMessages().size() > 0) {
      this.setVerified(false);
      throw new InvalidClaimException(
          "Message parameter verification failed. See Error object for details");
    }
    return hasError();
  }

}
