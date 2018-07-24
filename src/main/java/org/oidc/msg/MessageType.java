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

/**
 * Different types of request/response
 */
public enum MessageType {
  AUTHORIZATION_REQUEST, AUTHORIZATION_RESPONSE, TOKEN_RESPONSE, REFRESH_TOKEN_REQUEST, REFRESH_TOKEN_RESPONSE, USER_INFO, JSON_RESPONSE_DESCRIPTOR, PROVIDER_CONFIGURATION_RESPONSE, REGISTRATION_RESPONSE, REGISTRATION_REQUEST, REFRESH_ACCESS_TOKEN_REQUEST, ACCESS_TOKEN_REQUEST, CC_ACCESS_TOKEN_REQUEST, AS_CONFIGURATION_RESPONSE, ACCESS_TOKEN_RESPONSE, NONE_RESPONSE, RESOURCE_REQUEST, USER_INFO_REQUEST, ADDRESS_CLAIM, OPEN_ID_SCHEMA, ID_TOKEN, MESSAGE_WITH_ID_TOKEN, REFRESH_SESSION_REQUEST, WEBFINGER_REQUEST_MESSAGE;
}