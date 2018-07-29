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
import com.auth0.jwt.exceptions.oicmsg_exceptions.UnknownKeyType;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.msg.Key;
import com.auth0.msg.KeyBundle;
import com.auth0.msg.KeyJar;
import com.auth0.msg.KeyType;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.oidc.msg.oidc.IDToken;

/** Base class for tests offering helpers.*/
public abstract class BaseMessageTest {

  private static final String PRIVATE_KEY_FILE = "src/test/resources/rsa-private.pem";
  private static final String PUBLIC_KEY_FILE = "src/test/resources/rsa-public.pem";
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


   
  /**
   * Creates simple signed jwt.
   * 
   * @param alg slg to use.
   * @return simple jwt.
   * 
   */
  protected String getSignedJwt(String alg)
      throws IllegalArgumentException, ImportException, UnknownKeyType, ValueError {
    List<Key> keys = null;
    switch (alg) {
      case "RS256":
      case "RS384":
      case "RS512":
        keys = getKeyJarPrv().getSigningKey(KeyType.RSA.name(), keyOwner, null,
            null);
        break;
      case "ES256":
      case "ES384":
      case "ES512":
        keys = getKeyJarPrv().getSigningKey(KeyType.EC.name(), keyOwner, null,
            null);
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
    return JWT.create().withIssuer("op").sign(algorithm);
  }

  /**
   * Creates if needed one keyjar with one private rsa key.
   * 
   * @return keyjar
   * 
   */
  protected KeyJar getKeyJarPrv()
      throws ImportException, UnknownKeyType, IllegalArgumentException, ValueError {
    if (keyJarOfPrivateKeys != null) {
      return keyJarOfPrivateKeys;
    }
    keyJarOfPrivateKeys = new KeyJar();
    ArrayList<String> usesPrv = new ArrayList<String>();
    usesPrv.add("sig");
    usesPrv.add("dec");
    KeyBundle keyBundlePrv = KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", usesPrv);
    keyJarOfPrivateKeys.addKeyBundle(keyOwner, keyBundlePrv);
    return keyJarOfPrivateKeys;
  }
  
  /**
   * Creates if needed one keyjar with one public rsa key.
   * 
   * @return keyjar
   * 
   */
  protected KeyJar getKeyJarPub()
      throws ImportException, UnknownKeyType, IllegalArgumentException, ValueError {
    if (keyJarOfPublicKeys != null) {
      return keyJarOfPublicKeys;
    }
    keyJarOfPublicKeys = new KeyJar();
    ArrayList<String> usesPub = new ArrayList<String>();
    usesPub.add("ver");
    usesPub.add("enc");
    KeyBundle keyBundlePub = KeyBundle.keyBundleFromLocalFile(PUBLIC_KEY_FILE, "der", usesPub);
    keyJarOfPublicKeys.addKeyBundle(keyOwner, keyBundlePub);
    return keyJarOfPublicKeys;
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
   */
  protected String generateIdTokenNow(Map<String, Object> claims, Key key, String algo) throws InvalidClaimException {
    claims.put("iss", "issuer");
    claims.put("sub", "subject");
    claims.put("aud", "clientid");
    claims.put("exp", (System.currentTimeMillis() / 1000) + 10000);
    claims.put("iat", System.currentTimeMillis() / 1000);
    IDToken token = new IDToken(claims);
    token.verify();
    return token.toJwt(key, algo);
  }
  
}