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

package org.oidc.msg.validator;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.oidc.Link;

/**
 * Unit tests for [@link LinksClaimValidator}.
 */
public class LinksClaimValidatorTest extends BaseClaimValidatorTest<LinksClaimValidator> {

  @Before
  public void setup() {
    validator = new LinksClaimValidator();
  }

  @Test(expected = InvalidClaimException.class)
  public void testInvalidList() throws InvalidClaimException {
    validator.validate(Arrays.asList("not a link or map"));
  }

  @Test
  public void testValidLink() throws InvalidClaimException {
    Link link = new Link();
    link.addClaim("rel", "mockRel");
    List<Link> validated = validator.validate(Arrays.asList(link));
    Assert.assertEquals(1, validated.size());
    Assert.assertEquals(1, validated.get(0).getClaims().size());
    Assert.assertEquals("mockRel", validated.get(0).getClaims().get("rel"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testInvalidLink() throws InvalidClaimException {
    validator.validate(Arrays.asList(new Link()));
  }

  public void testValidMap() throws InvalidClaimException {
    Map<String, Object> map = new HashMap<>();
    map.put("rel", "mockRel");
    List<Link> validated = validator.validate(Arrays.asList(map));
    Assert.assertEquals(1, validated.size());
    Assert.assertEquals(1, validated.get(0).getClaims().size());
    Assert.assertEquals("mockRel", validated.get(0).getClaims().get("rel"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testInvalidMapContents() throws InvalidClaimException {
    validator.validate(Arrays.asList(new HashMap<String, Object>()));
  }

  @Test(expected = InvalidClaimException.class)
  public void testInvalidMapType() throws InvalidClaimException {
    Map<Long, Object> map = new HashMap<>();
    map.put(12L, "mockValue");
    validator.validate(Arrays.asList(map));
  }
}
