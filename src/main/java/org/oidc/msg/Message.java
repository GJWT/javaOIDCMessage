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

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.msg.Key;
import com.auth0.msg.KeyJar;

import java.net.MalformedURLException;
import java.util.List;
import java.util.Map;

/**
 * This interface all the methods related to message processing.
 */
public interface Message {

  /**
   * Serialize the content of this instance (the claims map) into a JSON object.
   * 
   * @return a JSON String representation of the message
   * @throws SerializationException Thrown if message cannot be serialized.
   */
  String toJson() throws SerializationException;

  /**
   * Serialize the content of the claims map into an UrlEncoded string.
   * 
   * @return a urlEncoded string
   * @throws SerializationException Thrown if message cannot be serialized.
   */
  String toUrlEncoded() throws SerializationException;

  /**
   * Serialize the content of this instance (the claims map) into a jwt string.
   * 
   * @param key
   *          signing key
   * @param alg
   *          signing algorithm
   * @return message as jwt string.
   * @throws SerializationException Thrown if message cannot be serialized.
   */
  String toJwt(Key key, String alg) throws SerializationException;

  /**
   * Constructs a message from the JSON string.
   * 
   * @param input The JSON String representation of a message
   * @throws DeserializationException Thrown if the message content is invalid.
   */
  void fromJson(String input) throws DeserializationException;

  /**
   * Constructs a message from the URL string.
   * 
   * @param input The urlEncoded String representation of a message.
   * @throws MalformedURLException Thrown if the message cannot be parsed from the input.
   * @throws DeserializationException Thrown if the message content is invalid.
   */
  void fromUrlEncoded(String input) throws MalformedURLException, DeserializationException;

  /**
   * Constructs message from JWT.
   * 
   * @param jwt
   *          the jwt String representation of a message
   * @param keyJar
   *          KeyJar having a key for verifying the signature. If null, signature is not verified.
   * @param keyOwner
   *          For whom the key belongs to.
   * @param noKidIssuers
   *          If jwt is missing kid, set the list of allowed kids in keyjar to verify jwt. if
   *          allowMissingKid is set to true, list is not used.
   * @param allowMissingKid
   *          If jwt is missing kid, try any of the owners keys to verify jwt.
   * @param trustJKU
   *          Whether extending keyjat by JKU is allowed or not.
   * @throws DeserializationException Thrown if the message content is invalid.
   * @throws JWTDecodeException Thrown if the JWT cannot be decoded.
   */
  public void fromJwt(String jwt, KeyJar keyJar, String keyOwner,
      Map<String, List<String>> noKidIssuers, boolean allowMissingKid, boolean trustJKU) throws DeserializationException, JWTDecodeException;

  /**
   * Adds a new claim to the message.
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
   * Get the verification error details.
   * 
   * @return the error object representing an error in verification
   */
  Error getError();

  /**
   * Whether the message has any verification errors.
   * 
   * @return boolean for whether there is an error in verification
   */
  boolean hasError();
  
  /**
   * Get the message parameter requirements.
   * 
   * @return Parameter requirements.
   */
  Map<String, ParameterVerificationDefinition> getParameterVerificationDefinitions();
}
