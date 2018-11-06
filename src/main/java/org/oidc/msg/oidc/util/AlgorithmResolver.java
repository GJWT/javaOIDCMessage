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

package org.oidc.msg.oidc.util;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.oicmsg_exceptions.HeaderError;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.msg.ECKey;
import com.auth0.msg.Key;
import com.auth0.msg.RSAKey;
import com.auth0.msg.SYMKey;
import java.io.UnsupportedEncodingException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class AlgorithmResolver {

  /**
   * Method verifies key and algorithm types match.
   * 
   * @param key
   *          to match
   * @param alg
   *          to match
   * @return true if the key and algorithm types match
   */
  private static boolean verifyKeyType(Key key, String alg) {
    switch (alg) {
      case "none":
        return true;
      case "RS256":
      case "RS384":
      case "RS512":
      case "RSA1_5":
      case "RSA-OAEP":
      case "RSA-OAEP-256":
        if (key instanceof RSAKey) {
          return true;
        }
        break;
      case "ES256":
      case "ES384":
      case "ES512":
      case "ECDH-ES":
      case "ECDH-ES+A128KW":
      case "ECDH-ES+A192KW":
      case "ECDH-ES+A256KW":
        if (key instanceof ECKey) {
          return true;
        }
        break;
      case "HS256":
      case "HS384":
      case "HS512":
      case "A128KW":
      case "A192KW":
      case "A256KW":
        if (key instanceof SYMKey) {
          return true;
        }
        break;
      default:
        break;
    }
    return false;
  }

  /**
   * Resolves signing algorithm for key and algorithm identifier string.
   * 
   * @param key
   *          for signing.
   * @param alg
   *          algorithm name.
   * @return Algorithm instance
   * @throws ValueError
   *           if key or algorithm is of unexpected type
   * @throws UnsupportedEncodingException
   *           if symmetric key encoding fails
   * @throws SerializationNotPossible
   *           if symmetric key fails to serialize
   */
  public static Algorithm resolveSigningAlgorithm(Key key, String alg)
      throws ValueError, UnsupportedEncodingException, SerializationNotPossible {
    if (!verifyKeyType(key, alg)) {
      throw new ValueError(String.format("key does not match algorithm '%s' ", alg));
    }
    if (key != null && !key.isPrivateKey()) {
      throw new ValueError(String.format("Siging key must be private"));
    }
    switch (alg) {
      case "none":
        return Algorithm.none();
      case "RS256":
        return Algorithm.RSA256(null, (RSAPrivateKey) key.getKey(true));
      case "RS384":
        return Algorithm.RSA384(null, (RSAPrivateKey) key.getKey(true));
      case "RS512":
        return Algorithm.RSA512(null, (RSAPrivateKey) key.getKey(true));
      case "ES256":
        return Algorithm.ECDSA256(null, (ECPrivateKey) key.getKey(true));
      case "ES384":
        return Algorithm.ECDSA384(null, (ECPrivateKey) key.getKey(true));
      case "ES512":
        return Algorithm.ECDSA512(null, (ECPrivateKey) key.getKey(true));
      case "HS256":
        return Algorithm.HMAC256((String) ((SYMKey) key).serialize(true).get("k"));
      case "HS384":
        return Algorithm.HMAC384((String) ((SYMKey) key).serialize(true).get("k"));
      case "HS512":
        return Algorithm.HMAC512((String) ((SYMKey) key).serialize(true).get("k"));
      default:
        break;
    }
    throw new ValueError(String.format("Algorithm '%s' not supported ", alg));
  }

  /**
   * Resolves signature verification algorithm for key and algorithm identifier string.
   * 
   * @param key
   *          for signing.
   * @param alg
   *          algorithm name.
   * @return Algorithm instance
   * @throws ValueError
   *           if key or algorithm is of unexpected type
   * @throws UnsupportedEncodingException
   *           if symmetric key encoding fails
   * @throws SerializationNotPossible
   *           if symmetric key fails to serialize
   */
  public static Algorithm resolveVerificationAlgorithm(Key key, String alg)
      throws ValueError, UnsupportedEncodingException, SerializationNotPossible {
    if (!verifyKeyType(key, alg)) {
      throw new ValueError(String.format("key does not match algorithm '%s' ", alg));
    }
    if (key != null && !key.isPublicKey()) {
      throw new ValueError(String.format("Verification key must be public"));
    }
    switch (alg) {
      case "none":
        return Algorithm.none();
      case "RS256":
        return Algorithm.RSA256((RSAPublicKey) key.getKey(false), null);
      case "RS384":
        return Algorithm.RSA384((RSAPublicKey) key.getKey(false), null);
      case "RS512":
        return Algorithm.RSA512((RSAPublicKey) key.getKey(false), null);
      case "ES256":
        return Algorithm.ECDSA256((ECPublicKey) key.getKey(false), null);
      case "ES384":
        return Algorithm.ECDSA384((ECPublicKey) key.getKey(false), null);
      case "ES512":
        return Algorithm.ECDSA512((ECPublicKey) key.getKey(false), null);
      case "HS256":
        return Algorithm.HMAC256((String) ((SYMKey) key).serialize(false).get("k"));
      case "HS384":
        return Algorithm.HMAC384((String) ((SYMKey) key).serialize(false).get("k"));
      case "HS512":
        return Algorithm.HMAC512((String) ((SYMKey) key).serialize(false).get("k"));
      default:
        break;
    }
    throw new ValueError(String.format("Algorithm '%s' not supported ", alg));
  }

  /**
   * Resolves key transport algorithm by key and algorithm identifier string.
   * 
   * @param key
   *          for signing.
   * @param alg
   *          algorithm name.
   * @return Algorithm instance
   * @throws ValueError
   *           if key or algorithm is of unexpected type
   * @throws UnsupportedEncodingException
   *           if symmetric key encoding fails
   * @throws SerializationNotPossible
   *           if symmetric key fails to serialize
   */
  public static Algorithm resolveKeyTransportAlgorithmForEncryption(Key key, String alg)
      throws ValueError, UnsupportedEncodingException, SerializationNotPossible {
    if (!verifyKeyType(key, alg)) {
      throw new ValueError(String.format("key does not match algorithm '%s' ", alg));
    }
    if (key == null || !key.isPublicKey()) {
      throw new ValueError(String.format("Key for key transport algorithm must be public"));
    }
    switch (alg) {
      case "RSA1_5":
        return Algorithm.RSA1_5((RSAPublicKey) key.getKey(false), null);
      case "RSA-OAEP":
        return Algorithm.RSAOAEP((RSAPublicKey) key.getKey(false), null);
      case "RSA-OAEP-256":
        return Algorithm.RSAOAEP256((RSAPublicKey) key.getKey(false), null);
      case "A128KW":
        return Algorithm.AES128Keywrap(((SYMKey) key).getKey(false).getEncoded());
      case "A192KW":
        return Algorithm.AES192Keywrap(((SYMKey) key).getKey(false).getEncoded());
      case "A256KW":
        return Algorithm.AES256Keywrap(((SYMKey) key).getKey(false).getEncoded());
        // TODO: Add missing algorithms
      default:
        break;
    }
    throw new ValueError(String.format("Algorithm '%s' not supported ", alg));
  }

  /**
   * Builds ephemeral key from jwt header parameters.
   * 
   * @param decodedJWT
   *          jwt containing ephemeral key
   * @return ephemeral key
   * @throws ValueError
   *           if unable to build ephemeral key
   */
  private static ECKey buildSenderEphemeralKey(DecodedJWT decodedJWT) throws ValueError {
    if (!(decodedJWT.getHeaderClaim("epk") instanceof Map)) {
      throw new ValueError(String.format("No ephemeral key in jwt '%s'", decodedJWT.toString()));
    }
    Map<String, Object> epk = decodedJWT.getHeaderClaim("epk").asMap();
    try {
      return ECKey
          .publicKeyBuilder((String) epk.get("crv"), (String) epk.get("x"), (String) epk.get("y"))
          .build();
    } catch (HeaderError | JWKException | ValueError | SerializationNotPossible e) {
      throw new ValueError("Unable to build ephemeral key:" + e.getMessage());
    }
  }

  /**
   * Resolves key transport algorithm by key and algorithm identifier string.
   * 
   * @param key
   *          decryption key.
   * @param decodedJWT
   *          jwe to decrypt.
   * @return Algorithm instance
   * @throws ValueError
   *           if key or algorithm is of unexpected type
   * @throws UnsupportedEncodingException
   *           if symmetric key encoding fails
   * @throws SerializationNotPossible
   *           if symmetric key fails to serialize
   */
  public static Algorithm resolveKeyTransportAlgorithmForDecryption(Key key, DecodedJWT decodedJWT)
      throws ValueError, UnsupportedEncodingException, SerializationNotPossible {
    if (!verifyKeyType(key, decodedJWT.getAlgorithm())) {
      throw new ValueError(
          String.format("key does not match algorithm '%s' ", decodedJWT.getAlgorithm()));
    }
    if (key == null || !key.isPrivateKey()) {
      throw new ValueError(String.format("Key for key transport algorithm must be private"));
    }
    switch (decodedJWT.getAlgorithm()) {
      case "RSA1_5":
        return Algorithm.RSA1_5(null, (RSAPrivateKey) key.getKey(true));
      case "RSA-OAEP":
        return Algorithm.RSAOAEP(null, (RSAPrivateKey) key.getKey(true));
      case "RSA-OAEP-256":
        return Algorithm.RSAOAEP256(null, (RSAPrivateKey) key.getKey(true));
      case "A128KW":
        return Algorithm.AES128Keywrap(((SYMKey) key).getKey(true).getEncoded());
      case "A192KW":
        return Algorithm.AES192Keywrap(((SYMKey) key).getKey(true).getEncoded());
      case "A256KW":
        return Algorithm.AES256Keywrap(((SYMKey) key).getKey(true).getEncoded());
      case "ECDH-ES":
        return Algorithm.ECDH_ES((ECPrivateKey) key.getKey(true), null,
            (ECPublicKey) buildSenderEphemeralKey(decodedJWT).getKey(false),
            decodedJWT.getHeaderClaim("apu").asString(), 
            decodedJWT.getHeaderClaim("apv").asString(),
            decodedJWT.getHeaderClaim("enc").asString(),
            Algorithm.getAlgorithmKeydataLen(decodedJWT.getHeaderClaim("enc").asString()));
      case "ECDH-ES+A128KW":
        return Algorithm.ECDH_ES_A128KW((ECPrivateKey) key.getKey(true), null,
            (ECPublicKey) buildSenderEphemeralKey(decodedJWT).getKey(false),
            decodedJWT.getHeaderClaim("apu").asString(), 
            decodedJWT.getHeaderClaim("apv").asString(),
            decodedJWT.getHeaderClaim("enc").asString(),
            Algorithm.getAlgorithmKeydataLen(decodedJWT.getHeaderClaim("enc").asString()));
      case "ECDH-ES+A192KW":
        return Algorithm.ECDH_ES_A192KW((ECPrivateKey) key.getKey(true), null,
            (ECPublicKey) buildSenderEphemeralKey(decodedJWT).getKey(false),
            decodedJWT.getHeaderClaim("apu").asString(), 
            decodedJWT.getHeaderClaim("apv").asString(),
            decodedJWT.getHeaderClaim("enc").asString(),
            Algorithm.getAlgorithmKeydataLen(decodedJWT.getHeaderClaim("enc").asString()));
      case "ECDH-ES+A256KW":
        return Algorithm.ECDH_ES_A256KW((ECPrivateKey) key.getKey(true), null,
            (ECPublicKey) buildSenderEphemeralKey(decodedJWT).getKey(false),
            decodedJWT.getHeaderClaim("apu").asString(), 
            decodedJWT.getHeaderClaim("apv").asString(),
            decodedJWT.getHeaderClaim("enc").asString(),
            Algorithm.getAlgorithmKeydataLen(decodedJWT.getHeaderClaim("enc").asString()));
      default:
        break;
    }
    throw new ValueError(String.format("Algorithm '%s' not supported ", decodedJWT.getAlgorithm()));
  }

}
