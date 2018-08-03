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

package org.oidc.msg.validator;

import org.oidc.msg.InvalidClaimException;

/**
 * The claim validators (1) checks whether the given {@link Object} contains a value that can be
 * transformed into target object format and (2) transforms them.
 *
 * @param <T>
 *          The target object format.
 */
public interface ClaimValidator<T> {

  /**
   * Validates and possibly transforms the value into the target format.
   * 
   * @param value
   *          The value to be validated (and transformed).
   * @return The validated value in target format.
   * @throws InvalidClaimException
   *           If the transformation cannot be done.
   */
  public T validate(Object value) throws InvalidClaimException;

}