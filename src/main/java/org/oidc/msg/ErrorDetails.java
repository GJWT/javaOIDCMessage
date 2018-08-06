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

  /** The parameter name whose verification failed. */
  private String parameterName;
  
  /** The verification error type. */
  private ErrorType errorType;
  
  /** The optional message describing why verification failed. */
  private String errorMessage;
  
  /** The optional exception related to the verification failure. */
  private Throwable errorCause;

  public ErrorDetails(String parameter, ErrorType type) {
    this(parameter, type, null, null);
  }
  
  public ErrorDetails(String parameter, ErrorType type, String message) {
    this(parameter, type, message, null);
  }

  public ErrorDetails(String parameter, ErrorType type, Throwable cause) {
    this(parameter, type, null, cause);
  }

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

  public String toString() {
    StringBuilder builder = new StringBuilder("parameterName=" + parameterName);
    builder.append(", errorType=" + errorType);
    builder.append(", errorMessage=" + errorMessage);
    builder.append(", errorCause=" + errorCause);
    return builder.toString();
  }
}
