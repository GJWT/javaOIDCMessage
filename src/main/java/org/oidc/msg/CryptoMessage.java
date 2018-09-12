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

import com.auth0.msg.KeyJar;
import java.util.List;
import java.util.Map;

/**
 * Interface implemented by message classes supporting jwt handling.
 */
public interface CryptoMessage {

  /**
   * Set the allowed encryption key transport algorithm.
   * 
   * @param encAlg
   *          the allowed encryption key transport algorithm
   */
  public void setEncAlg(String encAlg);

  /**
   * get the allowed encryption key transport algorithm.
   * 
   * @return the allowed encryption key transport algorithm
   */
  public String getEncAlg();

  /**
   * Set the allowed encryption algorithm.
   * 
   * @param encEnc
   *          the allowed encryption algorithm
   */
  public void setEncEnc(String encEnc);

  /**
   * Get the allowed encryption algorithm.
   * 
   * @return the allowed encryption algorithm
   */
  public String getEncEnc();

  /**
   * Set the allowed signing algorithm.
   * 
   * @param sigAlg
   *          the allowed id token signing algorithm
   */
  public void setSigAlg(String sigAlg);

  /**
   * Get the allowed signing algorithm.
   * 
   * @return the allowed id token signing algorithm
   */
  public String getSigAlg();

  /**
   * Set map of allowed kids for issuer.
   * 
   * @param noKidIssuers
   *          map of allowed kids for issuer
   */
  public void setNoKidIssuers(Map<String, List<String>> noKidIssuers);

  /**
   * Get map of allowed kids for issuer.
   * 
   * @return map of allowed kids for issuer
   */
  public Map<String, List<String>> getNoKidIssuers();

  /**
   * Set whether to trust jku header.
   * 
   * @param trustJku
   *          whether to trust jku header
   */
  public void setTrustJku(boolean trustJku);

  /**
   * Get whether to trust jku header.
   * 
   * @return whether to trust jku header
   */
  public boolean getTrustJku();

  /**
   * Set whether to allow missing kid when searching jwt key for signing.
   * 
   * @param allowMissingKid
   *          Whether to allow missing kid when searching jwt key for signing.
   */
  public void setAllowMissingKid(boolean allowMissingKid);

  /**
   * Get whether to allow missing kid when searching jwt key for signing.
   * 
   * @return Whether to allow missing kid when searching jwt key for signing.
   */
  public boolean getAllowMissingKid();

  /**
   * Set Key Jar for JWT verification keys. If not set verification is not done.
   * 
   * @param keyJar
   *          Key Jar for JWT verification keys.
   */
  public void setKeyJar(KeyJar keyJar);

  /**
   * Get Key Jar for JWT verification keys. If not set verification is not done.
   * 
   * @return Key Jar for JWT verification keys.
   */
  public KeyJar getKeyJar();

  /**
   * Set Issuer of keys.
   * 
   * @param issuer
   *          Issuer of keys.
   */
  public void setIssuer(String issuer);

  /**
   * Get Issuer of keys.
   * 
   * @return Issuer of keys.
   */
  public String getIssuer();

}
