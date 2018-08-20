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

package org.oidc.msg.oidc;

import org.junit.Test;
import org.oidc.msg.BaseMessageTest;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;

import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.Before;

/**
 * Unit tests for {@link JsonResponseDescriptor}.
 */
public class JsonResponseDescriptorTest extends BaseMessageTest<JsonResponseDescriptor> {

  @Before
  public void setup() {
    message = new JsonResponseDescriptor();
  }
  
  @Test
  public void testFromJson() throws InvalidClaimException, JsonProcessingException, DeserializationException {
    String json = "{ \"subject\" : \"acct:juliet%40capulet.example@shopping.example.com\",\n"
        + "   \"links\":\n" + "    [\n" + "     {\n"
        + "      \"rel\": \"http://openid.net/specs/connect/1.0/issuer\",\n"
        + "      \"href\": \"https://server.example.com\"\n" + "     }\n" + "    ]\n" + "  }";
    message = new JsonResponseDescriptor();
    message.fromJson(json);
    message.verify();
    Map<String, Object> claims = message.getClaims();
    Assert.assertEquals("acct:juliet%40capulet.example@shopping.example.com",
        claims.get("subject"));
    @SuppressWarnings("unchecked")
    List<Link> links = (List<Link>) claims.get("links");
    Assert.assertNotNull(links);
    Assert.assertEquals(links.size(), 1);
    Map<String, Object> linkClaims = links.get(0).getClaims();
    Assert.assertEquals("http://openid.net/specs/connect/1.0/issuer", linkClaims.get("rel"));
    Assert.assertEquals("https://server.example.com", linkClaims.get("href"));
  }

  @Test
  public void testFromClaims() throws JsonProcessingException, InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("subject", "acct:juliet%40capulet.example@shopping.example.com");
    List<Link> links = new ArrayList<Link>();
    Link link = new Link();
    link.addClaim("rel", "http://openid.net/specs/connect/1.0/issuer");
    link.addClaim("href", "https://server.example.com");
    links.add(link);
    claims.put("links", links);
    message = new JsonResponseDescriptor(claims);
    message.verify();
    Map<String, Object> parsedClaims = message.getClaims();
    Assert.assertEquals("acct:juliet%40capulet.example@shopping.example.com",
        parsedClaims.get("subject"));
    @SuppressWarnings("unchecked")
    List<Link> parsedLinks = (List<Link>) parsedClaims.get("links");
    Assert.assertNotNull(parsedLinks);
    Assert.assertEquals(parsedLinks.size(), 1);
    Map<String, Object> linkClaims = parsedLinks.get(0).getClaims();
    Assert.assertEquals("http://openid.net/specs/connect/1.0/issuer", linkClaims.get("rel"));
    Assert.assertEquals("https://server.example.com", linkClaims.get("href"));
  }

}
