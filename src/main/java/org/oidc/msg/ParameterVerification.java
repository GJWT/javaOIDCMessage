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

import org.oidc.msg.validator.ArrayClaimValidator;
import org.oidc.msg.validator.BooleanClaimValidator;
import org.oidc.msg.validator.DateClaimValidator;
import org.oidc.msg.validator.IntClaimValidator;
import org.oidc.msg.validator.ListClaimValidator;
import org.oidc.msg.validator.MapClaimValidator;
import org.oidc.msg.validator.StringClaimValidator;
import org.oidc.msg.validator.MessageClaimValidator;
import org.oidc.msg.validator.IDTokenClaimValidator;


/** Enum for expressing parameter verification definitions. */
public enum ParameterVerification {

  /** predefined verification types.*/ 
  SINGLE_REQUIRED_STRING(new ParameterVerificationDefinition(new StringClaimValidator(), true)), 
  SINGLE_OPTIONAL_STRING(new ParameterVerificationDefinition(new StringClaimValidator(), false)),
  SINGLE_REQUIRED_INT(new ParameterVerificationDefinition(new IntClaimValidator(), true)),
  SINGLE_OPTIONAL_INT(new ParameterVerificationDefinition(new IntClaimValidator(), false)),
  SINGLE_REQUIRED_BOOLEAN(new ParameterVerificationDefinition(new BooleanClaimValidator(), true)), 
  SINGLE_OPTIONAL_BOOLEAN(new ParameterVerificationDefinition(new BooleanClaimValidator(), false)),
  SINGLE_REQUIRED_DATE(new ParameterVerificationDefinition(new DateClaimValidator(), true)), 
  SINGLE_OPTIONAL_DATE(new ParameterVerificationDefinition(new DateClaimValidator(), false)),
  SINGLE_REQUIRED_MAP(new ParameterVerificationDefinition(new MapClaimValidator(), true)),
  SINGLE_OPTIONAL_MAP(new ParameterVerificationDefinition(new MapClaimValidator(), false)),
  REQUIRED_LIST_OF_STRINGS(new ParameterVerificationDefinition(new ListClaimValidator(), true)),
  OPTIONAL_LIST_OF_STRINGS(new ParameterVerificationDefinition(new ListClaimValidator(),false)),
  REQUIRED_LIST_OF_SP_SEP_STRINGS(
      new ParameterVerificationDefinition(new ArrayClaimValidator(), true)),
  OPTIONAL_LIST_OF_SP_SEP_STRINGS(
      new ParameterVerificationDefinition(new ArrayClaimValidator(), false)),
  SINGLE_REQUIRED_MESSAGE(new ParameterVerificationDefinition(new MessageClaimValidator(), true)), 
  SINGLE_OPTIONAL_MESSAGE(new ParameterVerificationDefinition(new MessageClaimValidator(), false)),
  SINGLE_REQUIRED_IDTOKEN(new ParameterVerificationDefinition(new IDTokenClaimValidator(), true)), 
  SINGLE_OPTIONAL_IDTOKEN(new ParameterVerificationDefinition(new IDTokenClaimValidator(), false));
  
 
  /** Verification definition. */
  private ParameterVerificationDefinition parameterVerificationDefinition;

  /**
   * Constructor.
   * 
   * @param parameterVerificationDefinition
   *          Verification definition.
   */
  private ParameterVerification(ParameterVerificationDefinition parameterVerificationDefinition) {
    this.parameterVerificationDefinition = parameterVerificationDefinition;
  }

  /**
   * Get the verification definition.
   * 
   * @return verification definition
   */
  public ParameterVerificationDefinition getValue() {
    return parameterVerificationDefinition;
  }

}
