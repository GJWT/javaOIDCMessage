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

import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Test;
import org.oidc.msg.oidc.util.TokenHash;

/**
 * Unit tests for {@link TokenHash}.
 */
public class TokenHashTest {

  @Test
  public void testHashSuccess() {
    String at = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
    Assert.assertThat("77QmUPtjPfzWtF2AnpK9RQ", CoreMatchers.is(TokenHash.compute(at, "RS256")));
    String c = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk";
    Assert.assertThat("LDktKdoQak3Pk0cnXxCltA", CoreMatchers.is(TokenHash.compute(c, "RS256")));
  }

  @Test
  public void testFailureUnknownAlgo() {
    String at = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
    Assert.assertNull(TokenHash.compute(at, "NOT_RS256"));
  }

}
