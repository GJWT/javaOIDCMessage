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

package org.oidc.msg;

import org.oidc.msg.validator.ClaimValidator;

/**
 * Class implementing definition on how request/response parameter existence should be verified.
 */
public class ParameterVerificationDefinition {

  /** Whether the parameter is required or not. */
  private boolean required = true;
  /** Claim validator used to validate the structure of the parameter value. */
  private ClaimValidator claimValidator;

  /**
   * Constructor.
   * 
   * @param validator
   *          claim validator used to validate the structure of the parameter value
   * @param required
   *          whether the parameter is required or not
   */
  public ParameterVerificationDefinition(ClaimValidator validator, boolean required) {
    this.claimValidator = validator;
    this.required = required;

  }

  /**
   * Get Whether the parameter is required or not.
   * 
   * @return true if the parameter must exist. false otherwise.
   */
  public boolean isRequired() {
    return required;
  }

  /**
   * Get the claim validator used to validate the structure of the parameter value.
   * 
   * @return Claim validator used to validate the structure of the parameter value
   */
  public ClaimValidator getClaimValidator() {
    return claimValidator;
  }

}
