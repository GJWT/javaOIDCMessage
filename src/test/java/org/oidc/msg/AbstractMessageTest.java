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

import com.auth0.jwt.impl.PayloadSerializer;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import org.junit.Before;
import org.junit.Test;

import org.junit.Assert;

import java.io.IOException;
import java.io.StringWriter;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;

public class AbstractMessageTest {
  private StringWriter writer;
  private PayloadSerializer serializer;
  private JsonGenerator jsonGenerator;
  private SerializerProvider serializerProvider;

  // TODO: Old tests start here. go through them and make sense out of them.

  @Before
  public void setUp() throws Exception {
    writer = new StringWriter();
    serializer = new PayloadSerializer();
    jsonGenerator = new JsonFactory().createGenerator(writer);
    ObjectMapper mapper = new ObjectMapper();
    jsonGenerator.setCodec(mapper);
    serializerProvider = mapper.getSerializerProvider();
  }

  @Test
  public void testToUrlEncoded() throws Exception {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("GRANT_TYPE", "refresh_token");

    MockMessage pcr = new MockMessage(claims);
    String pcrUrlEncoded = pcr.toUrlEncoded();
  }

  @Test
  public void testToJson() throws Exception {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("GRANT_TYPE", "refresh_token");

    MockMessage pcr = new MockMessage(claims);
    String pcrJson = pcr.toJson();
    String testJson = "{\"GRANT_TYPE\":\"refresh_token\"}";
    Assert.assertThat(pcrJson, is(testJson));
  }

  @Test
  public void testFromJson() throws Exception {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("GRANT_TYPE", "refresh_token");
    String testJson = "{\"GRANT_TYPE\":\"refresh_token\"}";
    MockMessage pcr = new MockMessage(claims);
    pcr.fromJson(testJson);
    Map<String, Object> claims2 = pcr.getClaims();

    Assert.assertEquals(pcr.getClaims(), claims);
  }

  // New tests ->

  @Test
  public void testFromJWT() throws IOException {
    // TODO: FromJWT does not verify signature. Once that is supported update this test.
    String idToken = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlz"
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
    HashMap<String, Object> claims = new HashMap<>();
    MockMessage mockMessage = new MockMessage(claims);
    mockMessage.fromJwt(idToken);
    Assert.assertEquals("http://server.example.com", mockMessage.getClaims().get("iss"));
    Assert.assertEquals("248289761001", mockMessage.getClaims().get("sub"));
    Assert.assertEquals("s6BhdRkqt3", mockMessage.getClaims().get("aud"));
    Assert.assertEquals("n-0S6_WzA2Mj", mockMessage.getClaims().get("nonce"));
    Assert.assertEquals(1311281970, mockMessage.getClaims().get("exp"));
    Assert.assertEquals(1311280970, mockMessage.getClaims().get("iat"));
    Assert.assertEquals("Jane Doe", mockMessage.getClaims().get("name"));
    Assert.assertEquals("Jane", mockMessage.getClaims().get("given_name"));
    Assert.assertEquals("Doe", mockMessage.getClaims().get("family_name"));
    Assert.assertEquals("female", mockMessage.getClaims().get("gender"));
    Assert.assertEquals("0000-10-31", mockMessage.getClaims().get("birthdate"));
    Assert.assertEquals("janedoe@example.com", mockMessage.getClaims().get("email"));
    Assert.assertEquals("http://example.com/janedoe/me.jpg",
        mockMessage.getClaims().get("picture"));
  }

  @Test(expected = InvalidClaimException.class)
  public void failureMissingRequiredParam() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "value");
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter2", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
  }

  @Test
  public void successMissingOptionalParams() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "value");
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter2", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    parVerDef.put("parameter3", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    parVerDef.put("parameter4", ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    parVerDef.put("parameter5", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"), "value");
  }

  @Test
  public void successTestStringType()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "value");
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"), "value");
    Assert.assertEquals(mockMessage.toJson(), "{\"parameter1\":\"value\"}");
  }

  @Test(expected = InvalidClaimException.class)
  public void failTestStringType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", 1);
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
  }

  @Test
  public void successTestIntType()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", new Long(5));
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"), 5L);
    Assert.assertEquals(mockMessage.toJson(), "{\"parameter1\":5}");
  }

  @Test
  public void successIntTypeConversion()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", new Integer(5));
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"), 5L);
    Assert.assertEquals(mockMessage.toJson(), "{\"parameter1\":5}");
  }

  @Test
  public void successIntTypeConversion2()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "57");
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"), 57L);
    Assert.assertEquals(mockMessage.toJson(), "{\"parameter1\":57}");
  }

  @Test(expected = InvalidClaimException.class)
  public void failTestIntType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "fail");
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
  }

  @SuppressWarnings("unchecked")
  @Test
  public void successTestListType()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    List<String> values = new ArrayList<String>();
    values.add("value");
    values.add("value2");
    claims.put("parameter1", values);
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(0), "value");
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(1),
        "value2");
    Assert.assertThat(mockMessage.toJson(), is("{\"parameter1\":[\"value\",\"value2\"]}"));
  }

  @SuppressWarnings("unchecked")
  @Test
  public void successTestListTypeAllowed()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    List<String> values = new ArrayList<String>();
    values.add("value");
    values.add("value2");
    claims.put("parameter1", values);
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    Map<String, List<?>> allowedValues = new HashMap<String, List<?>>();
    allowedValues.put("parameter1", Arrays.asList("value", "value2", "evenMore"));
    MockMessage mockMessage = new MockMessage(claims, parVerDef, allowedValues);
    mockMessage.verify();
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(0), "value");
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(1),
        "value2");
    Assert.assertThat(mockMessage.toJson(), is("{\"parameter1\":[\"value\",\"value2\"]}"));
  }

  @Test(expected = InvalidClaimException.class)
  public void failedTestListTypeNotAllAllowed()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    List<String> values = new ArrayList<String>();
    values.add("value");
    values.add("value2");
    claims.put("parameter1", values);
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    Map<String, List<?>> allowedValues = new HashMap<String, List<?>>();
    allowedValues.put("parameter1", Arrays.asList("value", "evenMore"));
    MockMessage mockMessage = new MockMessage(claims, parVerDef, allowedValues);
    mockMessage.verify();
  }

  @SuppressWarnings("unchecked")
  @Test
  public void successTestListTypeConversion()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "values");
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(0),
        "values");
    Assert.assertThat(mockMessage.toJson(), is("{\"parameter1\":[\"values\"]}"));
  }

  @SuppressWarnings("unchecked")
  @Test
  public void successTestListTypeConversionAllowed()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "values");
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    Map<String, List<?>> allowedValues = new HashMap<String, List<?>>();
    allowedValues.put("parameter1", Arrays.asList("values"));
    MockMessage mockMessage = new MockMessage(claims, parVerDef, allowedValues);
    mockMessage.verify();
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(0),
        "values");
    Assert.assertThat(mockMessage.toJson(), is("{\"parameter1\":[\"values\"]}"));
  }

  @Test(expected = InvalidClaimException.class)
  public void failedTestListTypeConversionNotAllowed()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "values");
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    Map<String, List<?>> allowedValues = new HashMap<String, List<?>>();
    allowedValues.put("parameter1", Arrays.asList("notValues"));
    MockMessage mockMessage = new MockMessage(claims, parVerDef, allowedValues);
    mockMessage.verify();
  }

  @SuppressWarnings("unchecked")
  @Test(expected = InvalidClaimException.class)
  public void failTestListType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    List<String> values = new ArrayList<String>();
    values.add("value");
    claims.put("parameter1", 1);
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(0),
        "values");
  }

  @Test
  public void successTestArrayType()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    String[] strArr = (String[]) Array.newInstance(String.class, 2);
    strArr[0] = "value";
    strArr[1] = "value2";
    claims.put("parameter1", strArr);
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.REQUIRED_LIST_OF_SP_SEP_STRINGS.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"), "value value2");
    Assert.assertThat(mockMessage.toJson(), is("{\"parameter1\":\"value value2\"}"));
  }

  @Test(expected = InvalidClaimException.class)
  public void failTestArrayType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", 1);
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.REQUIRED_LIST_OF_SP_SEP_STRINGS.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
  }

  @Test
  public void successTestBooleanType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", true);
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"), true);
  }

  @Test(expected = InvalidClaimException.class)
  public void failTestBooleanType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "value");
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
  }

  @Test
  public void successTestDateType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    Date date = new Date();
    claims.put("parameter1", date);
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_DATE.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
    Assert.assertEquals(((Date) mockMessage.getClaims().get("parameter1")).getTime(),
        date.getTime());
  }

  @Test
  public void successTestDateTypeConversion() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    Date date = new Date();
    claims.put("parameter1", date.getTime());
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_DATE.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
    Assert.assertEquals(((Date) mockMessage.getClaims().get("parameter1")).getTime(),
        date.getTime());
  }

  @Test(expected = InvalidClaimException.class)
  public void failTestDateType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "value");
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_DATE.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
  }

  @Test
  public void successTestMessageType() throws InvalidClaimException {
    HashMap<String, Object> innerClaims = new HashMap<>();
    innerClaims.put("parameter1", "value");
    Map<String, ParameterVerificationDefinition> innerParVerDef = new HashMap<String, ParameterVerificationDefinition>();
    innerParVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    MockMessage innerMockMessage = new MockMessage(innerClaims, innerParVerDef);

    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", innerMockMessage);
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_MESSAGE.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
    Assert.assertEquals(
        ((Message) (mockMessage.getClaims().get("parameter1"))).getClaims().get("parameter1"),
        "value");
  }
  
  @Test(expected = InvalidClaimException.class)
  public void failTestMessageType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "value");
    Map<String, ParameterVerificationDefinition> parVerDef = new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_MESSAGE.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.verify();
  }

  class MockMessage extends AbstractMessage {

    MockMessage(HashMap<String, Object> claims) {
      this(claims, new HashMap<String, ParameterVerificationDefinition>());
    }

    MockMessage(HashMap<String, Object> claims,
        Map<String, ParameterVerificationDefinition> parVerDef) {
      this(claims, parVerDef, new HashMap<String, List<?>>());
    }

    MockMessage(HashMap<String, Object> claims,
        Map<String, ParameterVerificationDefinition> parVerDef,
        Map<String, List<?>> allowedValues) {
      super(claims);
      for (String key : parVerDef.keySet()) {
        this.paramVerDefs.put(key, parVerDef.get(key));
      }
      for (String key : allowedValues.keySet()) {
        this.allowedValues.put(key, allowedValues.get(key));
      }
    }

  }
}