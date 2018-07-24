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

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

/**
 * This abstract class provides basic processing of messages.
 */
public abstract class AbstractMessage implements Message {
  /** Message request/response parameters. */
  private Map<String, Object> claims;
  /** Header when message is jwt like signed userinfo response. */
  private Map<String, Object> header;
  /** Json (de)serialization. */
  private ObjectMapper mapper = new ObjectMapper();
  /** Whether the message has been verified. */
  private boolean verified;
  /** Error if such has happened during message verification. */
  protected Error error = new Error();
  /** Parameter requirements. */
  protected final Map<String, ParameterVerificationDefinition> paramVerDefs = new HashMap<String, ParameterVerificationDefinition>();
  /** Default values for desired parameters. */
  protected final Map<String, Object> defaultValues = new HashMap<String, Object>();
  /** Allowed values for desired parameters. */
  protected final Map<String, List<?>> allowedValues = new HashMap<String, List<?>>();

  /**
   * Constructor.
   * 
   * @param claims
   *          message parameters
   */
  public AbstractMessage(Map<String, Object> claims) {
    this.claims = claims;
  }

  /**
   * Constructs message from urlEncoded String representation of a message.
   * 
   * @param input
   *          the urlEncoded String representation of a message
   */
  public void fromUrlEncoded(String input) throws MalformedURLException, IOException {
    String msgJson = StringUtils.newStringUtf8(Base64.decodeBase64(input));
    Map<String, Object> newClaims = mapper.readValue(msgJson,
        new TypeReference<Map<String, Object>>() {
        });
    this.claims = newClaims;
    verified = false;
  }

  /**
   * Takes the claims of this instance of the AbstractMessage class and serializes them to an
   * urlEncoded string.
   *
   * @return an urlEncoded string
   * @throws InvalidClaimException
   *           if the message is invalid
   */
  public String toUrlEncoded()
      throws SerializationException, JsonProcessingException, InvalidClaimException {
    String jsonMsg = mapper.writeValueAsString(this.claims);
    String urlEncodedMsg = Base64
        .encodeBase64URLSafeString(jsonMsg.getBytes(StandardCharsets.UTF_8));
    return urlEncodedMsg;
  }

  /**
   * Constructs message from JSON string values.
   * 
   * @param input
   *          The JSON String representation of a message
   */
  public void fromJson(String input) throws InvalidClaimException {
    Map<String, Object> newClaims;
    try {
      newClaims = mapper.readValue(input, new TypeReference<Map<String, Object>>() {
      });
    } catch (IOException e) {
      throw new InvalidClaimException(String.format("Unable to parse message from '%s'", input));
    }
    this.claims = newClaims;
    verified = false;
  }

  /**
   * Takes the parameters of this instance of the AbstractMessage class and serializes them to a
   * json string.
   *
   * @return a JSON String representation in the form of a hashMap mapping string -> string
   * @throws InvalidClaimException
   *           thrown if message parameters do not match the message requirements.
   */
  public String toJson() throws JsonProcessingException, InvalidClaimException {
    SimpleModule module = new SimpleModule();
    module.addSerializer(AbstractMessage.class, new MessageSerializer());
    mapper.registerModule(module);
    String jsonMsg = mapper.writeValueAsString(this);
    return jsonMsg;
  }

  /**
   * Constructs message from JWT.
   * 
   * @param input
   *          the jwt String representation of a message
   * @throws InvalidClaimException
   *           thrown if message parameters do not match the message requirements.
   */
  @SuppressWarnings("unchecked")
  public void fromJwt(String input) throws IOException {
    //TODO: This method should verify possible signature and decrypt if jwt is encrypted.
    //Requires keyjar.
    
    String[] parts = MessageUtil.splitToken(input);
    String headerJson;
    String payloadJson;
    try {
      headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
      payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
    } catch (NullPointerException e) {
      throw new JWTDecodeException("The UTF-8 Charset isn't initialized.", e);
    }
    this.header = mapper.readValue(headerJson, Map.class);
    this.claims = mapper.readValue(payloadJson, Map.class);
    verified = false;
  }

  /**
   * Serialize the content of this instance (the claims map) into a jwt string.
   * 
   * @param algorithm
   *          the algorithm to use in signing the JWT
   * @return a jwt String
   * @throws InvalidClaimException
   *           thrown if message parameters do not match the message requirements.
   */
  public String toJwt(Algorithm algorithm)
      throws JsonProcessingException, SerializationException, InvalidClaimException {
    header.put("alg", algorithm.getName());
    header.put("typ", "JWT");
    String signingKeyId = algorithm.getSigningKeyId();
    if (signingKeyId != null) {
      header.put("kid", signingKeyId);
    }
    JWTCreator.Builder newBuilder = JWT.create().withHeader(this.header);
    for (String claimName : claims.keySet()) {
      // TODO this needs to be extended for all claim types
      Object value = claims.get(claimName);
      if (value instanceof Boolean) {
        newBuilder.withClaim(claimName, (Boolean) value);
      } else if (value instanceof String) {
        newBuilder.withClaim(claimName, (String) value);
      } else if (value instanceof Date) {
        newBuilder.withClaim(claimName, (Date) value);
      } else if (value instanceof Long) {
        newBuilder.withClaim(claimName, (Long) value);
      }
    }
    return newBuilder.sign(algorithm);
  }

  /**
   * Adds default values to the claims which are not yet set.
   */
  protected void addDefaultValues() {
    for (String key : defaultValues.keySet()) {
      if (!this.claims.containsKey(key)) {
        this.claims.put(key, defaultValues.get(key));
      }
    }
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
    error.getMessages().clear();

    Map<String, ParameterVerificationDefinition> paramVerDefs = getParameterVerificationDefinitions();
    if (paramVerDefs == null || paramVerDefs.isEmpty()) {
      verified = true;
      return true;
    }
    for (String paramName : paramVerDefs.keySet()) {
      // If parameter is defined as REQUIRED, it must exist.
      if (paramVerDefs.get(paramName).isRequired()
          && (!claims.containsKey(paramName) || claims.get(paramName) == null)) {
        error.getMessages().add(String.format("Required parameter '%s' is missing", paramName));
      }
      Object value = claims.get(paramName);
      if (value == null) {
        continue;
      }
      // If parameter exists, we verify the type of it and possibly transform it.
      try {
        Object transformed = paramVerDefs.get(paramName).getClaimValidator().validate(value);
        claims.put(paramName, transformed);
      } catch (InvalidClaimException e) {
        error.getMessages().add(String.format("Parameter '%s' is not of expected type", paramName));
      }
    }
    for (String paramName : allowedValues.keySet()) {
      if (claims.containsKey(paramName)) {
        Object value = claims.get(paramName);
        List<?> allowed = allowedValues.get(paramName);
        boolean checked = true;
        if (allowed.isEmpty()) {
          checked = false;
        }
        if (value instanceof String) {
          if (!(allowed.get(0) instanceof String) || !allowed.contains(value)) {
            checked = false;
          }
        } else if (value instanceof Long) {
          if (!(allowed.get(0) instanceof Long) || !allowed.contains(value)) {
            checked = false;
          }
        } else if (value instanceof List) {
          for (Object item : (List<?>) value) {
            if (!allowed.contains(item)) {
              checked = false;
            }
          }
          // Should we support more value types?
        } else {
          checked = false;
        }
        if (!checked) {
          error.getMessages()
              .add(String.format("Parameter '%s' does not have expected value", paramName));
        }
      }
    }
    if (error.getMessages().size() > 0) {
      throw new InvalidClaimException(
          "Message parameter verification failed. See Error object for details");
    }
    verified = true;
    return true;
  }

  /**
   * Get error description of message parameter verification.
   * 
   * @return Error an object representing the error status of message parameter verification.
   */
  public Error getError() {
    return error;
  }

  /**
   * Get the message parameters.
   * 
   * @return List of the list of claims for this message
   */
  public Map<String, Object> getClaims() {
    return this.claims;
  }

  /**
   * add the claim to this instance of message.
   * 
   * @param name
   *          the name of the claim
   * @param value
   *          the value of the claim to add to this instance of Message
   */
  public void addClaim(String name, Object value) {
    this.claims.put(name, value);
    verified = false;
  }

  /**
   * Get parameter verification definitions.
   * 
   * @return parameter verification definitions
   */
  public Map<String, ParameterVerificationDefinition> getParameterVerificationDefinitions() {
    return this.paramVerDefs;
  }

  /**
   * Whether there is an error in verification.
   * 
   * @return boolean for whether there is an error in verification.
   */
  public boolean hasError() {
    return error.getMessages() != null;
  }

  /**
   * Whether the claims have been verified after last change.
   * 
   * @return true if verified, false otherwise.
   */
  public boolean isVerified() {
    return verified;
  }

  /**
   * Extending classes to set status.
   * 
   * @param verified
   *          false if the verification has failed in the extending class.
   */
  protected void setVerified(boolean verified) {
    this.verified = verified;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String toString() {
    // Override to return user friendly value
    return super.toString();
  }

}