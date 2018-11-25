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
import com.auth0.jwt.algorithms.CipherParams;
import com.auth0.jwt.algorithms.ECDHESAlgorithm;
import com.auth0.jwt.exceptions.KeyAgreementException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.HeaderError;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.msg.ECKey;
import com.auth0.msg.Key;
import com.auth0.msg.KeyJar;
import com.auth0.msg.RSAKey;
import com.auth0.msg.SYMKey;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.CharEncoding;
import org.bouncycastle.util.Arrays;

/** Class for verifying proposed key and algorithm match to create Algorithm. */
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
      case "A128GCMKW":
      case "A192GCMKW":
      case "A256GCMKW":  
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
      throw new ValueError(String.format("Signing key must be private"));
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
   * Helper creating symmetric key from byte string assumed to be client secret.
   * 
   * @param secret
   *          client secret.
   * @param keyLength
   *          length of the key required.
   * @return symmetric encryption/decryption key.
   * @throws ValueError
   *           of that type for convinience. Thrown if message diges caant be instantiated.
   */
  private static byte[] buildSymmetricCryptoKey(String secret, int keyLength) throws ValueError {
    try {
      if (keyLength <= 256) {
        return Arrays.copyOf(
            MessageDigest.getInstance("SHA-256").digest(secret.getBytes(CharEncoding.UTF_8)),
            keyLength / 8);
      } else if (keyLength <= 385) {
        return Arrays.copyOf(
            MessageDigest.getInstance("SHA-384").digest(secret.getBytes(CharEncoding.UTF_8)),
            keyLength / 8);
      } else {
        return Arrays.copyOf(
            MessageDigest.getInstance("SHA-512").digest(secret.getBytes(CharEncoding.UTF_8)),
            keyLength / 8);
      }
    } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
      throw new ValueError(
          String.format("Message digest required for key length '%d' cannot be instantiated, '%s'",
              keyLength, e.getMessage()));
    }
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
  public static Algorithm resolveKeyTransportAlgorithmForEncryption(Key key, String alg, String enc,
      KeyJar keyjar, String sender, String receiver)
      throws ValueError, UnsupportedEncodingException, SerializationNotPossible {
    if (!verifyKeyType(key, alg)) {
      throw new ValueError(String.format("key does not match algorithm '%s' ", alg));
    }
    if (alg.startsWith("ECDH") && !key.isPrivateKey()) {
      throw new ValueError(
          String.format("for ECDH family we need rp's own private key as transport key"));
    }
    switch (alg) {
      case "RSA1_5":
        return Algorithm.RSA1_5((RSAPublicKey) key.getKey(false), null);
      case "RSA-OAEP":
        return Algorithm.RSAOAEP((RSAPublicKey) key.getKey(false), null);
      case "RSA-OAEP-256":
        return Algorithm.RSAOAEP256((RSAPublicKey) key.getKey(false), null);
      case "A128KW":
        return Algorithm.AES128Keywrap(buildSymmetricCryptoKey(
            ((String) ((SYMKey) key).serialize(false).get("k")),
            Algorithm.getAlgorithmKeydataLen(alg)));
      case "A192KW":
        return Algorithm.AES192Keywrap(buildSymmetricCryptoKey(
            ((String) ((SYMKey) key).serialize(false).get("k")),
            Algorithm.getAlgorithmKeydataLen(alg)));
      case "A256KW":
        return Algorithm.AES256Keywrap(buildSymmetricCryptoKey(
            ((String) ((SYMKey) key).serialize(false).get("k")),
            Algorithm.getAlgorithmKeydataLen(alg)));
      case "ECDH-ES":
        return Algorithm.ECDH_ES((ECPrivateKey) key.getKey(true),
            (ECPublicKey) key.getKey(false),
            (ECPublicKey) getReceiverEphemeralKey(keyjar, receiver).getKey(false), sender, receiver,
            enc, Algorithm.getAlgorithmKeydataLen(enc));
      case "ECDH-ES+A128KW":
        return Algorithm.ECDH_ES_A128KW((ECPrivateKey) key.getKey(true),
            (ECPublicKey) key.getKey(false),
            (ECPublicKey) getReceiverEphemeralKey(keyjar, receiver).getKey(false), sender, receiver,
            "ECDH-ES+A128KW", Algorithm.getAlgorithmKeydataLen("ECDH-ES+A128KW"));
      case "ECDH-ES+A192KW":
        return Algorithm.ECDH_ES_A192KW((ECPrivateKey) key.getKey(true),
            (ECPublicKey) key.getKey(false),
            (ECPublicKey) getReceiverEphemeralKey(keyjar, receiver).getKey(false), sender, receiver,
            "ECDH-ES+A192KW", Algorithm.getAlgorithmKeydataLen("ECDH-ES+A192KW"));
      case "ECDH-ES+A256KW":
        return Algorithm.ECDH_ES_A256KW((ECPrivateKey) key.getKey(true),
            (ECPublicKey) key.getKey(false),
            (ECPublicKey) getReceiverEphemeralKey(keyjar, receiver).getKey(false), sender, receiver,
            "ECDH-ES+A256KW", Algorithm.getAlgorithmKeydataLen("ECDH-ES+A256KW"));
      default:
        break;
    }
    throw new ValueError(String.format("Algorithm '%s' not supported ", alg));
  }
  
  /**
   * Resolves content encryption algorithm.
   * 
   * @param encAlg
   *          key transport algorithm
   * @param encEnc
   *          name of the content encryption algorithm
   * @return content encryption algorithm
   * @throws KeyAgreementException
   */
  public static Algorithm resolveContentEncryptionAlg(Algorithm encAlg, String encEnc)
      throws KeyAgreementException {
    if (encAlg instanceof ECDHESAlgorithm) {
      return Algorithm.getContentEncryptionAlg(encEnc,
          CipherParams.getKeyAgreementInstance(encEnc, encAlg));
    }
    return Algorithm.getContentEncryptionAlg(encEnc, CipherParams.getInstance(encEnc));
  }
  
  /**
   * Gets receiver ephemeral key from keyjar. Any suitable located receiver key is treated as the
   * key.
   * 
   * @param keyjar
   *          KeyJar containing the ephemeral key
   * @param receiver
   *          receiver identifier, op issuer id
   * @return EC key or null
   * @throws ValueError
   *           if keyjar o
   */
  private static ECKey getReceiverEphemeralKey(KeyJar keyjar, String receiver) throws ValueError {
    if (keyjar == null) {
      throw new ValueError(
          "For ECDH family of key transports KeyJar is needed for receiver EC key");
    }
    if (receiver == null || receiver.isEmpty()) {
      throw new ValueError(
          "For ECDH family of key transports receiver is needed to locate EC key");
    }
    List<Key> keys = keyjar.getEncryptKey("EC", receiver, null, new HashMap<String,String>());
    if (keys.size() == 0) {
      throw new ValueError(String.format("No EC key for receiver '%s' in keyjar", receiver));
    }
    ECKey key = (ECKey) keys.get(0);
    if (key == null) {
      throw new ValueError(
          String.format("Not able to solve receiver ephemeral key for '%s'", receiver));
    }
    return key;
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
    
    if ((decodedJWT.getHeaderClaim("epk") == null)) {
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
        return Algorithm.AES128Keywrap(buildSymmetricCryptoKey(
            ((String) ((SYMKey) key).serialize(false).get("k")),
            Algorithm.getAlgorithmKeydataLen(decodedJWT.getAlgorithm())));
      case "A192KW":
        return Algorithm.AES192Keywrap(buildSymmetricCryptoKey(
            ((String) ((SYMKey) key).serialize(false).get("k")),
            Algorithm.getAlgorithmKeydataLen(decodedJWT.getAlgorithm())));
      case "A256KW":
        return Algorithm.AES256Keywrap(buildSymmetricCryptoKey(
            ((String) ((SYMKey) key).serialize(false).get("k")),
            Algorithm.getAlgorithmKeydataLen(decodedJWT.getAlgorithm())));
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
            decodedJWT.getHeaderClaim("alg").asString(),
            Algorithm.getAlgorithmKeydataLen(decodedJWT.getHeaderClaim("alg").asString()));
      case "ECDH-ES+A192KW":
        return Algorithm.ECDH_ES_A192KW((ECPrivateKey) key.getKey(true), null,
            (ECPublicKey) buildSenderEphemeralKey(decodedJWT).getKey(false),
            decodedJWT.getHeaderClaim("apu").asString(), 
            decodedJWT.getHeaderClaim("apv").asString(),
            decodedJWT.getHeaderClaim("alg").asString(),
            Algorithm.getAlgorithmKeydataLen(decodedJWT.getHeaderClaim("alg").asString()));
      case "ECDH-ES+A256KW":
        return Algorithm.ECDH_ES_A256KW((ECPrivateKey) key.getKey(true), null,
            (ECPublicKey) buildSenderEphemeralKey(decodedJWT).getKey(false),
            decodedJWT.getHeaderClaim("apu").asString(), 
            decodedJWT.getHeaderClaim("apv").asString(),
            decodedJWT.getHeaderClaim("alg").asString(),
            Algorithm.getAlgorithmKeydataLen(decodedJWT.getHeaderClaim("alg").asString()));
      default:
        break;
    }
    throw new ValueError(String.format("Algorithm '%s' not supported ", decodedJWT.getAlgorithm()));
  }

}
