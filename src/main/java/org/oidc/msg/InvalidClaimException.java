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

/**
 * An exception that is thrown when there is an invalid claim in a Message object type.
 */
@SuppressWarnings("serial")
public class InvalidClaimException extends Exception {
  
  /**
   * Constructor.
   * @param message The message describing the exception.
   */
  public InvalidClaimException(String message) {
    this(message, null);
  }

  /**
   * Constructor.
   * @param message The message describing the exception.
   * @param cause The cause for this exception.
   */
  public InvalidClaimException(String message, Throwable cause) {
    super(message, cause);
  }
}
