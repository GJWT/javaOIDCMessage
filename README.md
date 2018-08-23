# javaOIDCMessage

 NOTE: Work in progress. Part of the source code is copied from https://github.com/GJWT/java-jwt/tree/secondPR.

## Introduction

The [OpenID Connect (OIDC)](http://openid.net/specs/openid-connect-core-1_0.html) and [OAuth2](https://tools.ietf.org/html/rfc6749) standards define request and response messages - requests that are sent from clients to servers and responses from servers to clients.

This library allow us to:
* Instantiate and modify OIDC and OAuth2 messages from scratch or set of claims
* Verify the validity of the messages as well as the correctness of the claims that they contain
* Serialize the message into the correct on-the-wire representation (e.g. Json, URL encoded, JWT)
* Deserialize a received message from the on-the-wire representation (e.g. Json, URL encoded, JWT)

## Basic usage

All the messages implement the interface _org.oidc.msg.Message_. The OAuth2 -specific messages can be found from the _org.oidc.msg.oauth2_ package, as OIDC -specific messages are located at the _org.oidc.msg.oidc_ package.

The messages can be constructed from scratch and the claims added one by one:

```java
import org.oidc.msg.oidc.AuthenticationRequest;

...

	AuthenticationRequest message = new AuthenticationRequest();
	message.addClaim("response_type", "code");
	message.addClaim("client_id", "s6BhdRkqt3");
	message.addClaim("state", "xyz");
	message.addClaim("redirect_uri", "https://client.example.com/cb");

...
	
```

Or an use existing _Map_ can be exploited to provide the claims for the message constructor:

```java
import java.util.HashMap;
import java.util.Map;
import org.oidc.msg.oidc.AuthenticationRequest;

...

	Map<String, Object> claims = new HashMap<>();
	claims.put("response_type", "code");
	claims.put("client_id", "s6BhdRkqt3");
	claims.put("state", "xyz");
	claims.put("redirect_uri", "https://client.example.com/cb");
	AuthenticationRequest message = new AuthenticationRequest(claims);

...
	
```


## Serialization / deserialization

Since all the messages are used in an environment where information are to be sent over a wire it must be possible to serialize the information in such an instance to a format that can be transmitted over-the-wire.

Because of this a number of method has been added to support serialization to and deserialization from a number of representations that are used in the OAuth2 and OIDC protocol exchange.

The following three formats are supported:

* [JSON](https://www.json.org/)
* URL-encoded as defined in [RFC 3986](https://www.ietf.org/rfc/rfc3986.txt)
* JSON Web Token ([JWT](https://www.ietf.org/rfc/rfc7519.txt)) signed and/or encrypted.

An example using URL encoding:

```java
import org.oidc.msg.oidc.AuthenticationRequest;

...

	AuthenticationRequest message = new AuthenticationRequest();
	message.addClaim("response_type", "code");
	message.addClaim("client_id", "s6BhdRkqt3");
	message.addClaim("state", "xyz");
	message.addClaim("redirect_uri", "https://client.example.com/cb");
	System.out.println(message.toUrlEncoded());
...
	
```
```
?response_type=code&state=xyz&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&client_id=s6BhdRkqt3
```

Another example using JSON:

```java
import java.util.Arrays;
import org.oidc.msg.oidc.RegistrationRequest;

...

	RegistrationRequest message = new RegistrationRequest();
	message.addClaim("redirect_uris", Arrays.asList("https://client.example.com/cb", "https://client.example.com/cb2"));
	message.addClaim("response_types", Arrays.asList("code"));
	message.addClaim("application_type", "web");
	System.out.println(message.toJson());
...
	
```
```
{"application_type":"web","redirect_uris":["https://client.example.com/cb","https://client.example.com/cb2"],"response_types":["code"]}
```

And finally example using JWT, where also a _Key_ is needed for signing the JWT:

```java
import java.util.Arrays;
import java.util.Date;
import org.oidc.msg.oidc.IDToken;

...

    IDToken message = new IDToken();
    message.addClaim("iss", "https://issuer.example.com");
    message.addClaim("aud", Arrays.asList("https://client.example.com"));
    message.addClaim("sub", "mockSubject");
    message.addClaim("iat", new Date());
    Key key = new SYMKey("sig", "mockSecret");
    System.out.println(message.toJwt(key, "HS256"));

...
```
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOiJodHRwczovL2NsaWVudC5leGFtcGxlLmNvbSIsInN1YiI6Im1vY2tTdWJqZWN0IiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE1MzQ5NTc2Mjd9.k-3sS2TYxHwmmKfi3HI80IEDe8MadJDjWJIFc_MJVXc

```

## Verifying the message content

A protocol specification would not be anything if it didn’t specify what a message is supposed to look like. Which attributes that can occur in a message and what type of values the attributes could have. And in some extreme case the specification can also specify the exact values that a specific attribute can have.

The OAuth2 and OpenID Connect specifications does all that. But both of them also states that extra attributes can always occur and should be allowed.

All messages extending org.oidc.msg.AbstractMessage class can deal with this. Let’s make a basic error response message as an example. This message is defined as follows:

```java
import org.oidc.msg.AbstractMessage;
import org.oidc.msg.ParameterVerification;

public class ErrorMessage extends AbstractMessage {

  { // Set parameter requirements for message.
    paramVerDefs.put("error", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("error_description", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("error_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
  }

...

```

What this means is that *error* must have a _java.lang.String_ value and that *error_description* and *error_uri* may have values and if so single _java.lang.String_ values.

The following values for _org.oidc.msg.ParameterVerification_ are provided by the library off the shelf:

* *SINGLE_(OPTIONAL or REQUIRED)_STRING*: Value as _java.lang.String_.

* *SINGLE_(OPTIONAL or REQUIRED)_INT*: Value as _java.lang.Long_ or _java.lang.Integer_ or numeric _java.lang.String_ which are converted into _java.lang.Long_.

* *SINGLE_(OPTIONAL or REQUIRED)_BOOLEAN*: Value as _java.lang.Boolean_ or _java.lang.String_ containing _true_ or _false_, which are converted into _java.lang.Boolean_.

* *SINGLE_(OPTIONAL or REQUIRED)_DATE*: Value as _java.util.Date_ or _int_, _long_, _java.lang.Integer_ or _java_lang.Long_ containing epoch seconds, which are converted into _java.util.Date_.

* *SINGLE_(OPTIONAL or REQUIRED)_MAP*: Value as _java.util.Map_ with _java.lang.String_ as key format.

* *(OPTIONAL or REQUIRED)_LIST_OF_STRINGS*: Value as _java.util.List_ with _java.lang.String_ format, or single non-empty _java.lang.String_ which are converted into _java.util.List_.

* *(OPTIONAL or REQUIRED)_LIST_OF_SP_SEP_STRINGS*: Value as space-separated _java.lang.String_ or in non-empty array of _java.lang.String_s which are converted into space-separated _java.lang.String_.

* *SINGLE_(OPTIONAL or REQUIRED)_MESSAGE*: Value as any class implementing _org.oidc.msg.Message_ interface. The message is not verified.

* *SINGLE_(OPTIONAL or REQUIRED)_JWT*: Value as _java.lang.String_ that can be decoded into _com.auth0.JWT_. The JWT is not otherwise verified.

The messages can be verified using the _verify()_ method, see below:

```java

...

	ErrorMessage message = new ErrorMessage();
	message.addClaim("error", "invalid_request");
	System.out.println(message.verify());

...
```
```
true
```

As the only required attribute (*error*) is correctly defined the _verify()_ method will evaluate to _true_. If we forget to provide the error attribute, the method will evaluate to _false_ and the details for error can be contained via _getError()_ method:

```java

...

	ErrorMessage message = new ErrorMessage();
	message.addClaim("error_description", "Some strange error");
	if (!message.verify()) {
		System.out.println(message.getError().getDetails());
	}

...
```
```
[parameterName=error, errorType=MISSING_REQUIRED_VALUE, errorMessage=null, errorCause=null]
```

The _Error_ class contains a list of _ErrorDetails_, containing details for the incorrect parameter/attribute name and the error type. Optionally also the error message and the cause _Throwable_ may be included in the details.

In addition to the desired value format of the parameters, the allowed values can set in the following way:

```java
import java.util.Arrays;
import org.oidc.msg.AbstractMessage;
import org.oidc.msg.ParameterVerification;

public class ErrorMessage extends AbstractMessage {

  { // Set parameter requirements for message.
    paramVerDefs.put("error", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("error_description", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("error_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    allowedValues.put("error", Arrays.asList("invalid_request", "unauthorized_client")); 
  }

...

```

This way only the two values *invalid_request* or *unauthorized_client* are allowed for the *error* claim. See:

```java

...

    ErrorMessage message = new ErrorMessage();
    message.addClaim("error", "invalid_error");
    if (!message.verify()) {
      System.out.println(message.getError().getDetails());
    }

...
```
```
[parameterName=error, errorType=VALUE_NOT_ALLOWED, errorMessage=null, errorCause=null]
```