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

import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Map;

/**
 * This interface all the methods related to message processing.
 */
public interface Message {

  /**
   * Serialize the content of this instance (the claims map) into a JSON object
   * 
   * @return a JSON String representation of the message
   * @throws SerializationException
   */
  String toJson() throws SerializationException, JsonProcessingException, InvalidClaimException;

  /**
   * Serialize the content of the claims map into an UrlEncoded string
   * 
   * @return a urlEncoded string
   * @throws SerializationException
   */
  String toUrlEncoded()
      throws SerializationException, JsonProcessingException, InvalidClaimException;

  /**
   * Serialize the content of this instance (the claims map) into a jwt string
   * 
   * @param KeyJar
   *          the signing keyjar
   * @param String
   *          the algorithm to use in signing the JWT
   * @return a jwt String
   * @throws InvalidClaimException
   */
  String toJwt(Algorithm algorithm)
      throws SerializationException, JsonProcessingException, InvalidClaimException;

  /**
   * Logic to extract from the string the values
   * 
   * @param input
   *          The JSON String representation of a message
   */
  void fromJson(String input) throws InvalidClaimException;

  /**
   * @param input
   *          the urlEncoded String representation of a message
   */
  void fromUrlEncoded(String input)
      throws MalformedURLException, IOException, InvalidClaimException;

  /**
   *
   * @param input
   *          the jwt String representation of a message
   * @param KeyJar
   *          that might contain the necessary key
   */
  void fromJwt(String input) throws IOException;

  /**
   *
   * @param name
   *          of the claim
   * @param value
   *          of the claim
   */
  void addClaim(String name, Object value);

  /**
   * Verifies the presence of required message parameters. Verifies the the format of message
   * parameters.
   * 
   * @return true if parameters are successfully verified.
   * @throws InvalidClaimException
   *           if verification fails.
   */
  public boolean verify() throws InvalidClaimException;

  /**
   * Whether the message parameters have been verified after last change.
   * 
   * @return true if verified, false otherwise.
   */
  public boolean isVerified();

  /**
   * Get the message parameters.
   * 
   * @return List of the list of claims for this message
   */
  Map<String, Object> getClaims();

  /**
   * @return the error object representing an error in verification
   */
  Error getError();

  /**
   * @return boolean for whether there is an error in verification
   */
  boolean hasError();
  
  /**
   * @return Parameter requirements.
   */
  Map<String, ParameterVerificationDefinition> getParameterVerificationDefinitions();
}
