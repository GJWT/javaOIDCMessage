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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.oidc.Link;

public class LinksClaimValidator implements ClaimValidator {

  @Override
  public Object validate(Object value) throws InvalidClaimException {
    if (value instanceof List) {
      List<?> list = (List<?>) value;
      List<Link> links = new ArrayList<Link>();
      MapClaimValidator mapValidator = new MapClaimValidator();
      for (Object item : list) {
        Link link;
        if (item instanceof Map) {
          Map<String, Object> claims = (Map<String, Object>) mapValidator.validate(item);
          link = new Link(claims);
        } else if (item instanceof Link) {
          link = (Link) item;
        } else {
          throw new InvalidClaimException(
              String.format("Parameter '%s' is not of expected type", value));
        }
        // TODO: this is just for initiating verify()
        link.getClaims();
        links.add(link);
      }
      return links;
    }
    throw new InvalidClaimException(String.format("Parameter '%s' is not of expected type", value));
  }

}
