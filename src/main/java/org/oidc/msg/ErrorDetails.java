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
 * This class carries the information why a verification has failed for a specific parameter.
 */
public class ErrorDetails {

  /** T   * @param message The message describing the exception.
   * @param cause The cause for this exception.
 */
  private String parameterName;
  
  /** The verification error type. */
  private ErrorType errorType;
  
  /** The optional message describing why verification failed. */
  private String errorMessage;
  
  /** The optional exception related to the verification failure. */
  private Throwable errorCause;

  /**
   * Constructor.
   * @param parameter The parameter name whose verification failed.
   * @param type The verification error type.
   */
  public ErrorDetails(String parameter, ErrorType type) {
    this(parameter, type, null, null);
  }

  /**
   * Constructor.
   * @param parameter The parameter name whose verification failed.
   * @param type The verification error type.
   * @param message The optional message describing why verification failed.
   */
  public ErrorDetails(String parameter, ErrorType type, String message) {
    this(parameter, type, message, null);
  }

  /**
   * Constructor.
   * @param parameter The parameter name whose verification failed.
   * @param type The verification error type.
   * @param cause The optional exception related to the verification failure.
   */
  public ErrorDetails(String parameter, ErrorType type, Throwable cause) {
    this(parameter, type, null, cause);
  }

  /**
   * Constructor.
   * @param parameter The parameter name whose verification failed.
   * @param type The verification error type.
   * @param message The optional message describing why verification failed.
   * @param cause The optional exception related to the verification failure.
   */
  public ErrorDetails(String parameter, ErrorType type, String message, Throwable cause) {
    parameterName = parameter;
    errorType = type;
    errorMessage = message;
    errorCause = cause;
  }

  public String getParameterName() {
    return parameterName;
  }
  
  public ErrorType getErrorType() {
    return errorType;
  }
  
  public String getErrorMessage() {
    return errorMessage;
  }
  
  public Throwable getErrorCause() {
    return errorCause;
  }

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder("parameterName=" + parameterName);
    builder.append(", errorType=" + errorType);
    builder.append(", errorMessage=" + errorMessage);
    builder.append(", errorCause=" + errorCause);
    return builder.toString();
  }
}
