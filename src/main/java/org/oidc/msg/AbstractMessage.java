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
import com.auth0.jwt.JWTDecryptor;
import com.auth0.jwt.JWTEncryptor;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.KeyAgreementException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.msg.Key;
import com.auth0.msg.KeyJar;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.google.common.base.Strings;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.oidc.msg.oidc.util.AlgorithmResolver;

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
   * Constructs a message from the URL string.
   * 
   * @param input
   *          The urlEncoded String representation of a message.
   * @throws MalformedURLException
   *           Thrown if the message cannot be parsed from the input.
   * @throws InvalidClaimException
   *           Thrown if the message content is invalid.
   */
  public void fromUrlEncoded(String input) throws MalformedURLException, DeserializationException {
    if (Strings.isNullOrEmpty(input)) {
      return;
    }
    StringBuilder jsonBuilder = new StringBuilder("{ ");
    StringTokenizer paramTokenizer = new StringTokenizer(
        input.substring(input.startsWith("?") ? 1 : 0), "&");
    while (paramTokenizer.hasMoreTokens()) {
      String pair = paramTokenizer.nextToken();
      StringTokenizer pairTokenizer = new StringTokenizer(pair, "=");

      String key;
      String value;
      try {
        key = URLDecoder.decode(pairTokenizer.nextToken(), "UTF-8");
        value = URLDecoder.decode(pairTokenizer.nextToken(), "UTF-8");
      } catch (UnsupportedEncodingException e) {
        throw new MalformedURLException("The parameters cannot be decoded using UTF-8");
      }
      jsonBuilder.append("\"" + key + "\" : ");
      jsonBuilder.append(
          value.startsWith("{") || value.startsWith("[") ? "\"" + value.replace("\"", "\\\"") + "\""
              : "\"" + value + "\"");
      jsonBuilder.append(paramTokenizer.hasMoreTokens() ? "," : new String());
    }
    jsonBuilder.append("}");
    fromJson(jsonBuilder.toString());
  }

  /**
   * Takes the claims of this instance of the AbstractMessage class and serializes them to an
   * urlEncoded string.
   *
   * @return an urlEncoded string
   * @throws SerializationException
   *           Thrown if message cannot be serialized.
   */
  public String toUrlEncoded() throws SerializationException {
    if (claims.size() == 0) {
      return "";
    }
    JsonFactory factory = mapper.getFactory();
    JsonNode rootNode;
    try {
      JsonParser parser = factory.createParser(this.toJson());
      rootNode = mapper.readTree(parser);
    } catch (IOException e) {
      throw new SerializationException("Could not build the JSON", e);
    }
    StringBuilder query = new StringBuilder("");
    Iterator<String> keys = claims.keySet().iterator();
    while (keys.hasNext()) {
      String key = keys.next();
      JsonNode value = rootNode.get(key);
      try {
        String pair = URLEncoder.encode(key, "UTF-8") + "="
            + URLEncoder.encode(value.asText(), "UTF-8");
        query.append(keys.hasNext() ? pair + "&" : pair);
      } catch (UnsupportedEncodingException e) {
        throw new SerializationException("Could not URL encode the parameter", e);
      }
    }
    return query.toString();
  }

  /**
   * Constructs a message from the JSON string.
   * 
   * @param input
   *          The JSON String representation of a message
   * @throws InvalidClaimException
   *           Thrown if the message content is invalid.
   */
  public void fromJson(String input) throws DeserializationException {
    Map<String, Object> newClaims;
    try {
      newClaims = mapper.readValue(input, new TypeReference<Map<String, Object>>() {
      });
    } catch (IOException e) {
      throw new DeserializationException(String.format("Unable to parse message from '%s'", input));
    }
    this.claims = newClaims;
    verified = false;
  }

  /**
   * Takes the parameters of this instance of the AbstractMessage class and serializes them to a
   * json string.
   *
   * @return a JSON String representation in the form of a hashMap mapping string -> string
   * @throws SerializationException
   *           Thrown if message cannot be serialized.
   */
  public String toJson() throws SerializationException {
    SimpleModule module = new SimpleModule();
    module.addSerializer(AbstractMessage.class, new MessageSerializer());
    mapper.registerModule(module);
    try {
      return mapper.writeValueAsString(this);
    } catch (JsonProcessingException e) {
      throw new SerializationException("Could not serialize to JSON", e);
    }
  }

  /**
   * Constructs message from JWT. If JWT has no kid defined, allows to try with any otherwise
   * matching key in the bundle. Allows extending the keyjar by JKU.
   * 
   * @param jwt
   *          the jwt String representation of a message
   * @param keyJar
   *          KeyJar having a key for verifying the signature. If null, signature is not verified.
   * @param keyOwner
   *          For whom the key belongs to.
   * @throws IOException
   *           thrown if message parameters do not match the message requirements.
   */
  public void fromJwt(String jwt, KeyJar keyJar, String keyOwner) throws DeserializationException {
    fromJwt(jwt, keyJar, keyOwner, null, true, true);
  }

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
   *          Whether extending keyjar by JKU is allowed or not.
   * @throws DeserializationException
   *           Thrown if the message content is invalid.
   * @throws JWTDecodeException
   *           Thrown if the JWT cannot be decoded.
   */
  public void fromJwt(String jwt, KeyJar keyJar, String keyOwner,
      Map<String, List<String>> noKidIssuers, boolean allowMissingKid, boolean trustJKU)
      throws DeserializationException {
    fromJwt(jwt, keyJar, keyOwner, noKidIssuers, allowMissingKid, trustJKU, null, null, null);
  }

  
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
   *          Whether extending keyjar by JKU is allowed or not.
   * @param encAlg
   *          The allowed id token encryption key transport algorithm
   * @param encEnc
   *          The allowed id token encryption encryption algorithm
   * @param sigAlg
   *          The allowed id token signing algorithm
   * @throws JWTDecodeException
   *           Thrown if the JWT cannot be decoded.
   */
  public void fromJwt(String jwt, KeyJar keyJar, String keyOwner,
      Map<String, List<String>> noKidIssuers, boolean allowMissingKid, boolean trustJKU,
      String encAlg, String encEnc, String sigAlg) throws JWTDecodeException {

    try {
      jwt = parseFromToken(jwt, keyJar, encAlg, encEnc);
      if (jwt == null) {
        // successfully parsed from jwe(json)
        return;
      }
    } catch (IOException e) {
      throw new JWTDecodeException(
          String.format("Unable to parse JWT '%s': '%s'", jwt, e.getMessage()));
    }
    verified = false;
    if (keyJar == null) {
      return;
    }
    if (header.get("alg") == null || !(header.get("alg") instanceof String)) {
      throw new JWTDecodeException("JWT does not have alg in header");
    }
    String alg = (String) header.get("alg");
    if (sigAlg != null && !sigAlg.equals(alg)) {
      throw new JWTDecodeException(String.format(
          "JWT siging algorithm '%s' not matching the required algorithm '%s'", sigAlg, alg));
    }
    if ("none".equals(alg)) {
      Algorithm algorithm = Algorithm.none();
      JWTVerifier verifier = JWT.require(algorithm).build();
      verifier.verify(jwt);
      return;
    }
    //Now we expect to have keys
    List<Key> keys;
    try {
      keys = keyJar.getJWTVerifyKeys(jwt, keyOwner, noKidIssuers, allowMissingKid, trustJKU);
    } catch (JWKException | ValueError | IOException e) {
      throw new JWTDecodeException(
          String.format("Not able to locate keys to verify JWT, '%s'", e.getMessage()));
    }
    if (keys == null || keys.size() == 0) {
      throw new JWTDecodeException("Not able to locate keys to verify JWT");
    }
    // We try each located key
    for (Iterator<Key> iter = keys.iterator(); iter.hasNext();) {
      Key key = iter.next();
      try {
        JWT.require(AlgorithmResolver.resolveVerificationAlgorithm(key, alg)).build().verify(jwt);
        // Success
        return;
      } catch (JWTVerificationException | IllegalArgumentException | ValueError
          | UnsupportedEncodingException | SerializationNotPossible e) {
        if (iter.hasNext()) {
          //We move on to try next key
          continue;
        } else {
          throw new JWTDecodeException(String.format("Unable to verify JWT: '%s'", e.getMessage()));
        }
      }
    }
    throw new JWTDecodeException("Not able to verify JWT with any of the keys provided");
  }
  
  /**
   * Parses header and claims from JWT.
   * @param jwt jwt to parse.
   * @throws IOException if parsing fails. 
   */
  @SuppressWarnings("unchecked")
  private void parseFromJwt(String jwt)
      throws  IOException {
    String[] parts = MessageUtil.splitToken(jwt);
    String headerJson;
    String payloadJson;
    try {
      headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
      payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
    } catch (ArrayIndexOutOfBoundsException | NullPointerException e) {
      throw new JWTDecodeException("Not able to locate header and payload for JWT", e);
    }
    this.header = mapper.readValue(headerJson, Map.class);
    this.claims = mapper.readValue(payloadJson, Map.class);
  }
  
  /**
   * Parses header and claims from JWT or from JWE.
   * 
   * @param token
   *          jwe/jwt to parse from
   * @param keyJar
   *          key jar used, must not be null for jwe
   * @param keyOwner
   *          key owner, may be null
   * @param encAlg
   *          key transport algorithm required, may be null.
   * @param encEnc
   *          enc algorithm required, may be null.
   * @return jwt or null if response was json
   * @throws JWTDecodeException
   *           if unable to decrypt jwe
   * @throws IOException
   *           if parsing of jwt fails
   */
  private String parseFromToken(String token, KeyJar keyJar, String encAlg, String encEnc)
      throws JWTDecodeException, IOException {
    DecodedJWT decodedJwt = JWT.decode(token);
    if (!decodedJwt.isJWE()) {
      parseFromJwt(token);
      return token;
    }
    if (keyJar == null) {
      throw new JWTDecodeException("KeyJar not set for decrypting JWE");
    }
    List<Key> keys = keyJar.getDecryptKey(null, "", decodedJwt.getKeyId(), null);
    //We try with each suitable private key we have
    for (Iterator<Key> iter = keys.iterator(); iter.hasNext();) {
      Key key = iter.next();
      Algorithm decyptionAlg;
      try {
        decyptionAlg = AlgorithmResolver.resolveKeyTransportAlgorithmForDecryption(key, decodedJwt);
      } catch (ValueError | UnsupportedEncodingException | SerializationNotPossible e) {
        if (iter.hasNext()) {
          // We move on to try next key
          continue;
        } else {
          throw new JWTDecodeException(
              String.format("Unable to decrypt JWE: '%s'", e.getMessage()));
        }
      }
      JWTDecryptor decryptor = new JWTDecryptor(decyptionAlg);
      String decryptedJwe = new String(decryptor.decrypt(token));
      // Now we have a string that should be either jwt or json
      try {
        parseFromJwt(decryptedJwe);
        return decryptedJwe;
      } catch (Exception e) {
        // no op, we try our luck with json
      }
      try {
        fromJson(decryptedJwe);
        return null;
      } catch (Exception e) {
        // no op if we have still more keys
        if (iter.hasNext()) {
          continue;
        } else {
          throw new JWTDecodeException(
              String.format("Unable to decode decrypted JWE '%s'", decryptedJwe));
        }
      }
      
    }

    throw new JWTDecodeException("Unable to decrypt JWE with any of the keys provided");
  }

  /**
   * Serialize the content of this instance (the claims map) into a jwt string.
   * 
   * @param signingKey
   *          signing key
   * @param alg
   *          signing algorithm name
   * @param transportKey
   *          key transport key, if null encryption is not done.
   * @param encAlg
   *          key transport algorithm name. Must not be null if transportKey is set.
   * @param encEnc
   *          content encryption algorithm name. Must not be null if transportKey is set.
   * @param keyjar
   *          key jar containing receiver ephemeral public key when using ECDH family of key transport
   * @param sender
   *          sender i.e. client id
   * @param receiver
   *          receiver i.e. issuer id of the o.                            
   * @return message as jwt string.
   */
  
  public String toJwt(Key signingKey, String alg, Key transportKey, String encAlg, String encEnc, KeyJar keyjar, String sender, String receiver)
      throws SerializationException {
    header = new HashMap<String, Object>();
    header.put("alg", alg);
    header.put("typ", "JWT");
    if (signingKey != null && !Strings.isNullOrEmpty(signingKey.getKid())) {
      header.put("kid", signingKey.getKid());
    }
    Algorithm algorithm = null;
    try {
      algorithm = AlgorithmResolver.resolveSigningAlgorithm(signingKey, alg);
    } catch (IllegalArgumentException | ValueError | UnsupportedEncodingException
        | SerializationNotPossible e) {
      throw new SerializationException(String
          .format("Not able to initialize algorithm '%s' to sign JWT, '%s'", alg, e.getMessage()));
    }
    JWTCreator.Builder newBuilder = JWT.create().withHeader(this.header);
    for (String claimName : claims.keySet()) {
      Object value = claims.get(claimName);
      if (value instanceof Boolean) {
        newBuilder.withClaim(claimName, (Boolean) value);
      } else if (value instanceof String) {
        newBuilder.withClaim(claimName, (String) value);
      } else if (value instanceof Date) {
        newBuilder.withClaim(claimName, (Date) value);
      } else if (value instanceof Long) {
        newBuilder.withClaim(claimName, (Long) value);
      } else if (value instanceof List<?>) {
        if (((List<?>) value).get(0) instanceof String) {
          newBuilder.withArrayClaim(claimName, ((List<?>) value).toArray(new String[0]));
        } else if (((List<?>) value).get(0) instanceof Long) {
          newBuilder.withArrayClaim(claimName, ((List<?>) value).toArray(new Long[0]));
        }
      }

    }
    
    String signedJwt = newBuilder.sign(algorithm);
    if (transportKey == null) {
      return signedJwt;
    }
    if (encAlg == null || encEnc == null) {
      throw new SerializationException(
          "encAlg and encEnc are mandatory parameters if transport key is set");
    }
    try {
      Algorithm keyTransportAlgorithm = AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(
          transportKey, encAlg, encEnc, keyjar, sender, receiver);
      Algorithm contentEncryptionAlgorithm = AlgorithmResolver
          .resolveContentEncryptionAlg(keyTransportAlgorithm, encEnc);
      return JWTEncryptor.init().withPayload(signedJwt.getBytes("UTF-8"))
          .encrypt(keyTransportAlgorithm, contentEncryptionAlgorithm);
    } catch (UnsupportedEncodingException | ValueError | SerializationNotPossible
        | KeyAgreementException e) {
      throw new SerializationException(
          String.format("Not able to initialize key transport algorithm '%s' to encrypt JWS, '%s'",
              encAlg, e.getMessage()));
    }
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
   * parameters. If any messages extending this class wants to do any additional verifications, they
   * should implement it in the doVerify() method.
   * 
   * @return true if parameters are successfully verified.
   */
  public final boolean verify() {
    error.getDetails().clear();
    verified = true;

    Map<String, ParameterVerificationDefinition> paramVerDefs = getParameterVerificationDefinitions();
    if (paramVerDefs == null || paramVerDefs.isEmpty()) {
      return true;
    }
    for (String paramName : paramVerDefs.keySet()) {
      // If parameter is defined as REQUIRED, it must exist.
      if (paramVerDefs.get(paramName).isRequired()
          && (!claims.containsKey(paramName) || claims.get(paramName) == null)) {
        ErrorDetails details = new ErrorDetails(paramName, ErrorType.MISSING_REQUIRED_VALUE);
        error.getDetails().add(details);
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
        ErrorDetails details = new ErrorDetails(paramName, ErrorType.INVALID_VALUE_FORMAT, e);
        error.getDetails().add(details);
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
          String[] values = ((String) value).split(" ");
          for (String item : values) {
            if (!(allowed.get(0) instanceof String) || !allowed.contains(item)) {
              checked = false;
            }
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
          ErrorDetails details = new ErrorDetails(paramName, ErrorType.VALUE_NOT_ALLOWED);
          error.getDetails().add(details);
        }
      }
    }
    if (error.getDetails().size() > 0) {
      if (!isValidStructure()) {
        verified = false;
        return false;
      }
    }
    doVerify();
    setVerified(!hasError());
    return !hasError();
  }

  /**
   * Extension point for any extending classes to add further verifications to the message. If any
   * errors are found, the implementations must add the details to the list getError().getDetails().
   */
  protected void doVerify() {
  }

  /**
   * Tests if the structure is valid, i.e. parameters are not having unexpected format in the value.
   *
   * @return true if structure is verified.
   */
  protected boolean isValidStructure() {
    for (ErrorDetails details : error.getDetails()) {
      if (ErrorType.INVALID_VALUE_FORMAT.equals(details.getErrorType())) {
        return false;
      }
    }
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
    return !error.getDetails().isEmpty();
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
