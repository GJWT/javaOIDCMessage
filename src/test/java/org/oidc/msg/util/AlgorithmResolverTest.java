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

package org.oidc.msg.util;

import com.auth0.jwt.exceptions.oicmsg_exceptions.HeaderError;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.msg.ECKey;
import com.auth0.msg.KeyBundle;
import com.auth0.msg.KeyJar;
import com.auth0.msg.RSAKey;
import com.auth0.msg.SYMKey;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;

import org.junit.Assert;
import org.junit.Test;
import org.oidc.msg.oidc.util.AlgorithmResolver;

/**
 * Unit tests for {@link AlgorithmResolver}.
 */
public class AlgorithmResolverTest {

  KeyPair keyPairRSA = RSAKey.generateRSAKeyPair(2048);
  KeyPair keyPairEC_P256 = ECKey.generateECKeyPair("P-256");
  KeyPair keyPairEC_P256_Remote = ECKey.generateECKeyPair("P-256");
  KeyPair keyPairEC_P384 = ECKey.generateECKeyPair("P-384");
  KeyPair keyPairEC_P521 = ECKey.generateECKeyPair("P-521");

  @Test
  public void testResolveSigningAlgorithmSuccess() throws UnsupportedEncodingException, ValueError,
      SerializationNotPossible, JWKException, HeaderError {
    Assert.assertNotNull(AlgorithmResolver.resolveSigningAlgorithm(null, "none"));
    RSAKey rsaKey = RSAKey.keyBuilder(keyPairRSA.getPrivate()).build();
    Assert.assertNotNull(AlgorithmResolver.resolveSigningAlgorithm(rsaKey, "RS256"));
    Assert.assertNotNull(AlgorithmResolver.resolveSigningAlgorithm(rsaKey, "RS384"));
    Assert.assertNotNull(AlgorithmResolver.resolveSigningAlgorithm(rsaKey, "RS512"));

    ECKey ecKey256 = ECKey.keyBuilder(keyPairEC_P256.getPrivate()).build();
    Assert.assertNotNull(AlgorithmResolver.resolveSigningAlgorithm(ecKey256, "ES256"));
    ECKey ecKey384 = ECKey.keyBuilder(keyPairEC_P384.getPrivate()).build();
    Assert.assertNotNull(AlgorithmResolver.resolveSigningAlgorithm(ecKey384, "ES384"));
    ECKey ecKey521 = ECKey.keyBuilder(keyPairEC_P521.getPrivate()).build();
    Assert.assertNotNull(AlgorithmResolver.resolveSigningAlgorithm(ecKey521, "ES512"));

    SYMKey symKey = new SYMKey("thisisthesecret", "sig");
    Assert.assertNotNull(AlgorithmResolver.resolveSigningAlgorithm(symKey, "HS256"));
    Assert.assertNotNull(AlgorithmResolver.resolveSigningAlgorithm(symKey, "HS384"));
    Assert.assertNotNull(AlgorithmResolver.resolveSigningAlgorithm(symKey, "HS512"));
  }

  @Test(expected = ValueError.class)
  public void testResolveSigningAlgorithmFailureNullKey() throws UnsupportedEncodingException,
      ValueError, SerializationNotPossible, JWKException, HeaderError {
    AlgorithmResolver.resolveSigningAlgorithm(null, "RS256");
  }

  @Test(expected = ValueError.class)
  public void testResolveSigningAlgorithmFailureKeyMismatch() throws UnsupportedEncodingException,
      ValueError, SerializationNotPossible, JWKException, HeaderError {
    ECKey ecKey256 = ECKey.keyBuilder(keyPairEC_P256.getPrivate()).build();
    AlgorithmResolver.resolveSigningAlgorithm(ecKey256, "RS256");
  }

  @Test(expected = ValueError.class)
  public void testResolveSigningAlgorithmFailureNotPrivate() throws UnsupportedEncodingException,
      ValueError, SerializationNotPossible, JWKException, HeaderError {
    RSAKey rsaKey = RSAKey.keyBuilder(keyPairRSA.getPublic()).build();
    AlgorithmResolver.resolveSigningAlgorithm(rsaKey, "RS256");
  }

  @Test(expected = ValueError.class)
  public void testResolveSigningAlgorithmUnKnown() throws UnsupportedEncodingException, ValueError,
      SerializationNotPossible, JWKException, HeaderError {
    SYMKey symKey = new SYMKey("thisisthesecret", "sig");
    Assert.assertNotNull(AlgorithmResolver.resolveSigningAlgorithm(symKey, "_HS999"));
  }

  @Test
  public void testResolveVerificationAlgorithmSuccess() throws UnsupportedEncodingException,
      ValueError, SerializationNotPossible, JWKException, HeaderError {
    Assert.assertNotNull(AlgorithmResolver.resolveVerificationAlgorithm(null, "none"));
    RSAKey rsaKey = RSAKey.keyBuilder(keyPairRSA.getPublic()).build();
    Assert.assertNotNull(AlgorithmResolver.resolveVerificationAlgorithm(rsaKey, "RS256"));
    Assert.assertNotNull(AlgorithmResolver.resolveVerificationAlgorithm(rsaKey, "RS384"));
    Assert.assertNotNull(AlgorithmResolver.resolveVerificationAlgorithm(rsaKey, "RS512"));

    ECKey ecKey256 = ECKey.keyBuilder(keyPairEC_P256.getPublic()).build();
    Assert.assertNotNull(AlgorithmResolver.resolveVerificationAlgorithm(ecKey256, "ES256"));
    ECKey ecKey384 = ECKey.keyBuilder(keyPairEC_P384.getPublic()).build();
    Assert.assertNotNull(AlgorithmResolver.resolveVerificationAlgorithm(ecKey384, "ES384"));
    ECKey ecKey521 = ECKey.keyBuilder(keyPairEC_P521.getPublic()).build();
    Assert.assertNotNull(AlgorithmResolver.resolveVerificationAlgorithm(ecKey521, "ES512"));

    SYMKey symKey = new SYMKey("thisisthesecret", "sig");
    Assert.assertNotNull(AlgorithmResolver.resolveVerificationAlgorithm(symKey, "HS256"));
    Assert.assertNotNull(AlgorithmResolver.resolveVerificationAlgorithm(symKey, "HS384"));
    Assert.assertNotNull(AlgorithmResolver.resolveVerificationAlgorithm(symKey, "HS512"));
  }

  @Test(expected = ValueError.class)
  public void testResolveVerificationAlgorithmFailureNullKey() throws UnsupportedEncodingException,
      ValueError, SerializationNotPossible, JWKException, HeaderError {
    AlgorithmResolver.resolveVerificationAlgorithm(null, "RS256");
  }

  @Test(expected = ValueError.class)
  public void testResolveVerificationAlgorithmFailureKeyMismatch()
      throws UnsupportedEncodingException, ValueError, SerializationNotPossible, JWKException,
      HeaderError {
    ECKey ecKey256 = ECKey.keyBuilder(keyPairEC_P256.getPrivate()).build();
    AlgorithmResolver.resolveVerificationAlgorithm(ecKey256, "RS256");
  }

  @Test(expected = ValueError.class)
  public void testResolveVerificationAlgorithmFailurePrivate() throws UnsupportedEncodingException,
      ValueError, SerializationNotPossible, JWKException, HeaderError {
    RSAKey rsaKey = RSAKey.keyBuilder(keyPairRSA.getPrivate()).build();
    AlgorithmResolver.resolveVerificationAlgorithm(rsaKey, "RS256");
  }

  @Test(expected = ValueError.class)
  public void testResolveVerificationAlgorithmFailureUnknown() throws UnsupportedEncodingException,
      ValueError, SerializationNotPossible, JWKException, HeaderError {
    SYMKey symKey = new SYMKey("thisisthesecret", "sig");
    Assert.assertNotNull(AlgorithmResolver.resolveVerificationAlgorithm(symKey, "_HS999"));
  }

  @Test
  public void testResolveKeyTransportAlgorithmForEncryptionSuccess() throws ValueError,
      SerializationNotPossible, JWKException, HeaderError, ImportException, IOException {
    Assert.assertNotNull(AlgorithmResolver.resolveSigningAlgorithm(null, "none"));
    RSAKey rsaKey = RSAKey.keyBuilder(keyPairRSA.getPublic()).build();

    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(rsaKey,
        "RSA1_5", null, null, null, null));
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(rsaKey,
        "RSA-OAEP", null, null, null, null));
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(rsaKey,
        "RSA-OAEP-256", null, null, null, null));

    SYMKey symKey = new SYMKey("thisisthesecret", "enc");
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(symKey,
        "A128KW", null, null, null, null));
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(symKey,
        "A192KW", null, null, null, null));
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(symKey,
        "A256KW", null, null, null, null));

    ECKey ecKey256 = ECKey.keyBuilder(keyPairEC_P256.getPrivate()).build();
    KeyJar keyjar = new KeyJar();
    KeyBundle bundle = new KeyBundle();
    bundle.append(ECKey.keyBuilder(keyPairEC_P256_Remote.getPublic()).build());
    keyjar.addKeyBundle("receiver", bundle);

    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(ecKey256,
        "ECDH-ES", "A128CBC-HS256", keyjar, "sender", "receiver"));
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(ecKey256,
        "ECDH-ES+A128KW", null, keyjar, "sender", "receiver"));
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(ecKey256,
        "ECDH-ES+A192KW", null, keyjar, "sender", "receiver"));
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(ecKey256,
        "ECDH-ES+A256KW", null, keyjar, "sender", "receiver"));
  }

  @Test(expected = ValueError.class)
  public void testResolveKeyTransportAlgorithmFailureNullKey() throws UnsupportedEncodingException,
      ValueError, SerializationNotPossible, JWKException, HeaderError {
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(null, "RSA1_5",
        null, null, null, null));
  }

  @Test(expected = ValueError.class)
  public void testResolveKeyTransportAlgorithmFailureKeyMismatch()
      throws UnsupportedEncodingException, ValueError, SerializationNotPossible, JWKException,
      HeaderError {
    RSAKey rsaKey = RSAKey.keyBuilder(keyPairRSA.getPublic()).build();
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(rsaKey,
        "A128KW", null, null, null, null));
  }

  @Test(expected = ValueError.class)
  public void testResolveKeyTransportAlgorithmFailurePublic() throws ValueError,
      SerializationNotPossible, JWKException, HeaderError, ImportException, IOException {
    ECKey ecKey256 = ECKey.keyBuilder(keyPairEC_P256.getPublic()).build();
    KeyJar keyjar = new KeyJar();
    KeyBundle bundle = new KeyBundle();
    bundle.append(ECKey.keyBuilder(keyPairEC_P256_Remote.getPublic()).build());
    keyjar.addKeyBundle("receiver", bundle);
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(ecKey256,
        "ECDH-ES", "A128CBC-HS256", keyjar, "sender", "receiver"));

  }

  @Test(expected = ValueError.class)
  public void testResolveKeyTransportAlgorithmFailureUnknown() throws UnsupportedEncodingException,
      ValueError, SerializationNotPossible, JWKException, HeaderError {
    SYMKey symKey = new SYMKey("thisisthesecret", "enc");
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(symKey,
        "NOT_KNOWN_ALG", null, null, null, null));
  }

  @Test(expected = ValueError.class)
  public void testResolveKeyTransportAlgorithmFailureNoKeyJar() throws UnsupportedEncodingException,
      ValueError, SerializationNotPossible, JWKException, HeaderError {
    ECKey ecKey256 = ECKey.keyBuilder(keyPairEC_P256.getPrivate()).build();
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(ecKey256,
        "ECDH-ES", "A128CBC-HS256", null, "sender", "receiver"));
  }

  @Test(expected = ValueError.class)
  public void testResolveKeyTransportAlgorithmFailureNoReceiver() throws ValueError,
      SerializationNotPossible, JWKException, HeaderError, ImportException, IOException {
    ECKey ecKey256 = ECKey.keyBuilder(keyPairEC_P256.getPrivate()).build();
    KeyJar keyjar = new KeyJar();
    KeyBundle bundle = new KeyBundle();
    bundle.append(ECKey.keyBuilder(keyPairEC_P256_Remote.getPublic()).build());
    keyjar.addKeyBundle("receiver", bundle);
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(ecKey256,
        "ECDH-ES", "A128CBC-HS256", keyjar, "sender", null));
  }

  @Test(expected = ValueError.class)
  public void testResolveKeyTransportAlgorithmFailureNoKeyInBundle() throws ValueError,
      SerializationNotPossible, JWKException, HeaderError, ImportException, IOException {
    ECKey ecKey256 = ECKey.keyBuilder(keyPairEC_P256.getPrivate()).build();
    KeyJar keyjar = new KeyJar();
    Assert.assertNotNull(AlgorithmResolver.resolveKeyTransportAlgorithmForEncryption(ecKey256,
        "ECDH-ES", "A128CBC-HS256", keyjar, "sender", "receiver"));
  }

}
