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

import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

public class MessageSerializer extends StdSerializer<AbstractMessage> {

  public MessageSerializer() {
    this(null);
  }

  public MessageSerializer(Class<AbstractMessage> t) {
    super(t);
  }

  @Override
  public void serialize(AbstractMessage value, JsonGenerator gen, SerializerProvider provider)
      throws IOException {
    gen.writeStartObject();
    Map<String, Object> claims = value.getClaims();
    for (Entry<String, Object> entry : claims.entrySet()) {
      gen.writeObjectField(entry.getKey(), entry.getValue());
    }
    gen.writeEndObject();

  }
}
