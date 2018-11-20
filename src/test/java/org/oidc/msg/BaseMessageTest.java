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
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.UnknownKeyType;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.msg.Key;
import com.auth0.msg.KeyBundle;
import com.auth0.msg.KeyJar;
import com.auth0.msg.SYMKey;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;
import org.oidc.msg.oidc.ClaimsRequest;
import org.oidc.msg.oidc.IDToken;

/** Base class for tests offering helpers. */
public abstract class BaseMessageTest<T extends AbstractMessage> {

  /** The message to be tested. */
  protected T message;

  private static final String PRIVATE_KEY_FILE = "src/test/resources/rsa-private.pem";
  private static final String PUBLIC_KEY_FILE = "src/test/resources/rsa-public.pem";
  private static final String PUBLIC_KEY_FILE2 = "src/test/resources/rsa-public2.pem";
  //TODO: return keyOwner to https://issuer.example.com once edmund explains how parameter is used in getJWTVerifyKeys 
  protected String keyOwner = "https://issuer.example.com";
  protected KeyJar keyJarOfPrivateKeys = null;
  protected KeyJar keyJarOfPublicKeys = null;
  protected String signedJwt = null;

  protected String idToken = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlz"
      + "cyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4"
      + "Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAi"
      + "bi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEz"
      + "MTEyODA5NzAsCiAibmFtZSI6ICJKYW5lIERvZSIsCiAiZ2l2ZW5fbmFtZSI6"
      + "ICJKYW5lIiwKICJmYW1pbHlfbmFtZSI6ICJEb2UiLAogImdlbmRlciI6ICJm"
      + "ZW1hbGUiLAogImJpcnRoZGF0ZSI6ICIwMDAwLTEwLTMxIiwKICJlbWFpbCI6"
      + "ICJqYW5lZG9lQGV4YW1wbGUuY29tIiwKICJwaWN0dXJlIjogImh0dHA6Ly9l"
      + "eGFtcGxlLmNvbS9qYW5lZG9lL21lLmpwZyIKfQ.rHQjEmBqn9Jre0OLykYNn"
      + "spA10Qql2rvx4FsD00jwlB0Sym4NzpgvPKsDjn_wMkHxcp6CilPcoKrWHcip"
      + "R2iAjzLvDNAReF97zoJqq880ZD1bwY82JDauCXELVR9O6_B0w3K-E7yM2mac"
      + "AAgNCUwtik6SjoSUZRcf-O5lygIyLENx882p6MtmwaL1hd6qn5RZOQ0TLrOY"
      + "u0532g9Exxcm-ChymrB4xLykpDj3lUivJt63eEGGN6DH5K6o33TcxkIjNrCD"
      + "4XB1CKKumZvCedgHHF3IAK4dVEDSUoGlH9z4pP_eWYNXvqQOjGs-rDaQzUHl" + "6cQQWNiDpWOl_lxXjQEvQ";

  @Test
  public void testEmptyClaimsValidity() {
    boolean containsRequired = false;
    for (String key : message.getParameterVerificationDefinitions().keySet()) {
      ParameterVerificationDefinition parVerDef = message.getParameterVerificationDefinitions()
          .get(key);
      if (parVerDef.isRequired() && !message.getClaims().containsKey(key)) {
        containsRequired = true;
      }
    }
    if (containsRequired) {
      Assert.assertFalse(message.verify());
    } else {
      Assert.assertTrue(message.verify());
    }
  }

  @Test
  public void testDefaultValuesExists() {
    for (String key : message.defaultValues.keySet()) {
      Assert.assertEquals(message.defaultValues.get(key), message.getClaims().get(key));
    }
  }

  /**
   * Creates simple signed jwt.
   * 
   * @param alg
   *          slg to use.
   * @return simple jwt.
   * @throws JWKException 
   * @throws IOException 
   * 
   */
  protected String getSignedJwt(String alg)
      throws IllegalArgumentException, ImportException, UnknownKeyType, ValueError, IOException, JWKException {
    List<Key> keys = null;
    switch (alg) {
      case "RS256":
      case "RS384":
      case "RS512":
        keys = getKeyJar().getSigningKey("RSA", keyOwner, null, null);
        break;
      case "ES256":
      case "ES384":
      case "ES512":
        keys = getKeyJar().getSigningKey("EC", keyOwner, null, null);
        break;
      default:
        break;
    }
    Key key = keys == null ? null : keys.get(0);
    Algorithm algorithm = null;
    switch (alg) {
      case "none":
        algorithm = Algorithm.none();
        break;
      case "RS256":
        algorithm = Algorithm.RSA256(null, (RSAPrivateKey) key.getKey(true));
        break;
      case "RS384":
        algorithm = Algorithm.RSA384(null, (RSAPrivateKey) key.getKey(true));
        break;
      case "RS512":
        algorithm = Algorithm.RSA512(null, (RSAPrivateKey) key.getKey(true));
        break;
      case "ES256":
        algorithm = Algorithm.ECDSA256(null, (ECPrivateKey) key.getKey(true));
        break;
      case "ES384":
        algorithm = Algorithm.ECDSA384(null, (ECPrivateKey) key.getKey(true));
        break;
      case "ES512":
        algorithm = Algorithm.ECDSA512(null, (ECPrivateKey) key.getKey(true));
        break;
      default:
        break;
    }
    return JWT.create().withIssuer(keyOwner).sign(algorithm);
  }

  /**
   * Creates if needed one keyjar with one private rsa key.
   * 
   * @return keyjar
   * @throws JWKException 
   * @throws IOException 
   * 
   */
  protected KeyJar getKeyJar()
      throws ImportException, UnknownKeyType, IllegalArgumentException, ValueError, IOException, JWKException {
    if (keyJarOfPrivateKeys != null) {
      return keyJarOfPrivateKeys;
    }
    keyJarOfPrivateKeys = new KeyJar();
    ArrayList<String> usesPrv = new ArrayList<String>();
    usesPrv.add("sig");
    usesPrv.add("dec");
    KeyBundle keyBundlePrv = KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", usesPrv);
    keyJarOfPrivateKeys.addKeyBundle(keyOwner, keyBundlePrv);
    keyJarOfPrivateKeys.addKeyBundle("", keyBundlePrv);
    keyBundlePrv.append(new SYMKey("enc", Base64.encodeBase64URLSafeString(
        "1234567890123456".getBytes(Charset.forName("UTF-8")))));
    keyBundlePrv.append(new SYMKey("enc", Base64.encodeBase64URLSafeString(
        "123456789012345678901234".getBytes(Charset.forName("UTF-8")))));
    keyBundlePrv.append(new SYMKey("enc", Base64.encodeBase64URLSafeString(
        "12345678901234567890123456789012".getBytes(Charset.forName("UTF-8")))));
    ArrayList<String> usesPub = new ArrayList<String>();
    usesPub.add("ver");
    usesPub.add("enc");
    KeyBundle keyBundlePub = KeyBundle.keyBundleFromLocalFile(PUBLIC_KEY_FILE, "der", usesPub);
    keyJarOfPrivateKeys.addKeyBundle(keyOwner, keyBundlePub);
    
    return keyJarOfPrivateKeys;
  }

  /**
   * Creates if needed one keyjar with one public rsa key.
   * 
   * @return keyjar
   * @throws JWKException 
   * @throws IOException 
   * 
   */
  protected KeyJar getKeyJarPub()
      throws ImportException, UnknownKeyType, IllegalArgumentException, ValueError, IOException, JWKException {
    if (keyJarOfPublicKeys != null) {
      return keyJarOfPublicKeys;
    }
    keyJarOfPublicKeys = new KeyJar();
    ArrayList<String> usesPub = new ArrayList<String>();
    usesPub.add("ver");
    usesPub.add("enc");
    KeyBundle keyBundlePub = KeyBundle.keyBundleFromLocalFile(PUBLIC_KEY_FILE, "der", usesPub);
    keyBundlePub.append(new SYMKey("enc", Base64.encodeBase64URLSafeString(
        "1234567890123456".getBytes(Charset.forName("UTF-8")))));
    keyBundlePub.append(new SYMKey("enc", Base64.encodeBase64URLSafeString(
        "123456789012345678901234".getBytes(Charset.forName("UTF-8")))));
    keyBundlePub.append(new SYMKey("enc", Base64.encodeBase64URLSafeString(
        "12345678901234567890123456789012".getBytes(Charset.forName("UTF-8")))));
    keyJarOfPublicKeys.addKeyBundle(keyOwner, keyBundlePub);
    return keyJarOfPublicKeys;
  }
  
  /**
   * Creates a second key jar with no corresponding private key.
   * 
   * @return keyjar
   * @throws JWKException 
   * @throws IOException 
   * 
   */
  protected KeyJar getKeyJarPub2()
      throws ImportException, UnknownKeyType, IllegalArgumentException, ValueError, IOException, JWKException {
    KeyJar keyJarOfPublicKeys2 = new KeyJar();
    ArrayList<String> usesPub = new ArrayList<String>();
    usesPub.add("ver");
    usesPub.add("enc");
    KeyBundle keyBundlePub = KeyBundle.keyBundleFromLocalFile(PUBLIC_KEY_FILE2, "der", usesPub);
    keyJarOfPublicKeys2.addKeyBundle(keyOwner, keyBundlePub);
    return keyJarOfPublicKeys2;
  }

  /**
   * Generates simple id token jwt string for tests
   * 
   * @param claims
   *          any additional to add to minimal set. Must not be null but may be empty.
   * @param key
   *          signing key or null
   * @param algo
   *          algorithm used to sign, may be none
   * @return
   * @throws InvalidClaimException
   * @throws SerializationException 
   */
  protected String generateIdTokenNow(Map<String, Object> claims, Key key, String algo)
      throws InvalidClaimException, SerializationException {
    claims.put("iss", keyOwner);
    claims.put("sub", "subject");
    claims.put("aud", "clientid");
    claims.put("exp", (System.currentTimeMillis() / 1000) + 5);
    claims.put("iat", new Date());
    IDToken token = new IDToken(claims);
    token.verify();
    return token.toJwt(key, algo, null, null, null, null, null, null);
  }

  /**
   * Helper to generate claims request.
   */
  protected ClaimsRequest getClaimsRequest() throws InvalidClaimException {
    Map<String, Object> userInfoClaimsRequestMembers = new HashMap<String, Object>();
    Map<String, Object> essentialTrue = new HashMap<String, Object>();
    essentialTrue.put("essential", true);
    userInfoClaimsRequestMembers.put("given_name", essentialTrue);
    userInfoClaimsRequestMembers.put("nickname", null);
    userInfoClaimsRequestMembers.put("email", essentialTrue);
    userInfoClaimsRequestMembers.put("email_verified", essentialTrue);
    userInfoClaimsRequestMembers.put("picture", null);
    userInfoClaimsRequestMembers.put("http://example.info/claims/groups", null);
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("userinfo", userInfoClaimsRequestMembers);
    Map<String, Object> acrParams = new HashMap<String, Object>();
    acrParams.put("essential", true);
    List<String> acrValues = new ArrayList<String>();
    acrValues.add("urn:mace:incommon:iap:silver");
    acrValues.add("urn:mace:incommon:iap:bronze");
    acrParams.put("values", acrValues);
    Map<String, Object> idTokenClaimsRequestMembers = new HashMap<String, Object>();
    idTokenClaimsRequestMembers.put("acr", acrParams);
    Map<String, Object> value = new HashMap<String, Object>();
    value.put("value", "248289761001");
    idTokenClaimsRequestMembers.put("sub", value);
    idTokenClaimsRequestMembers.put("auth_time", essentialTrue);
    claims.put("idtoken", idTokenClaimsRequestMembers);
    ClaimsRequest message = new ClaimsRequest(claims);
    message.verify();
    return message;
  }

}