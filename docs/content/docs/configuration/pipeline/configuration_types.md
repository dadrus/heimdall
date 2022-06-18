---
title: "Configuration Types"
date: 2022-06-09T18:56:56+02:00
lastmod: 2022-06-09T18:56:56+02:00
draft: true
toc: true
menu:
  docs:
    weight: 60
    parent: "Pipeline"
---

## Assertions

This type enables configuration of required token and claim assertions. Depending on the object type (JWT or introspection response), the assertions apply to different parts of such objects.

| Name                 | Type                                              | Mandatory | Description                                                                                                                                                                      |
|----------------------|---------------------------------------------------|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `scopes`             | *[Scopes Matcher]({{< ref "#scopes-matcher" >}})* | no        | Required scopes given to the client.                                                                                                                                             |
| `audience`           | *string array*                                    | no        | Required entries in the `aud` claim. Both cases, either as whitespace separated string, or a JSON array are considered.                                                          |
| `issuers`            | *string array*                                    | yes       | Issuers to trust. At least one issuer must be configured                                                                                                                         |
| `allowed_algorithms` | *string array*                                    | no        | Algorithms, which are trusted (according to [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)). Defaults to the following list: ES256, ES384, ES512, PS256, PS384, PS512 |
| `validity_leeway`    | *[Duration]({{< ref "#duration" >}})*             | yes       | The time leeway to consider while verifying the `iat`, `exp` and the `nbf`.                                                                                                      |

**Example**

```.yaml
issuers:
 - foo
 - bar
audience:
 - zap
scopes:
 - baz
allowed_algorithms:
 - ES512
validity_leeway: 5s
```

Here we say, the token must have been issued either by the issuer `foo`, or the issuer `bar`, the `aud` claim must contain `zap`, the scope (either `scp` or `scope` must be present and contain the scope `baz`, if the token or the introspection response is signed, it must have been signed by using the `ES512` algorithm (ECDSA using P-521 and SHA-512) and if the information about token validity is present, we respect a deviation of 5 seconds.

## Authentication Data Source

An authentication data source is actually a list of possible strategies for subject authentication data retrieval. The entries following the first one are fallbacks and are only executed if the previous strategy could not retrieve the required authentication data from the request.

This fallback mechanism can become handy, if different clients of your application send the authentication data using different methods. [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) describes for example how to use bearer tokens in HTTP requests to access OAuth 2.0 protected resources. This RFC says, a token can either be sent in the `Authorization` header, or in a query parameter, or even as part of the HTTP body. So you can define the following list to let Heimdall try to extract the access token from all three places:

```.yaml
- header: Authorization
  strip_prefix: Bearer
- query_parameter: access_token
- body_parameter: access_token
```

The available strategies are described in the following sections.

### Cookie Strategy

This strategy can retrieve authentication data from a specific HTTP cookie. Following properties are supported:

| Name           | Type     | Mandatory | Description                                             |
|----------------|----------|-----------|---------------------------------------------------------|
| `cookie`       | *string* | yes       | The name of the cookie to use.                          |

**Example**

Imagine you want Heimdall to verify an authentication session, which is represented by a specific cookie before the request hits your upstream service. If the client of your upstream application, which is case of a cookie would usually be a browser sends a cookie named "session", you can inform Heimdall to extract and use it by configuring this strategy as follows:

```.yaml
- cookie: session
```

### Header Strategy

This strategy can retrieve authentication data from a specific HTTP header. Following properties are supported:

| Name           | Type     | Mandatory | Description                                                                                                                                                   |
|----------------|----------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `header`       | *string* | yes       | The name of the header to use.                                                                                                                                |
| `strip_prefix` | *string* | no        | Prefix, which should be stripped from the header value. Stripping the prefix doesn't always make sense. Consider the scopes in which this strategy is applied |

**Example**

Imagine you want Heimdall to verify an access token used to protect your upstream service. If the client of your upstream application sends the access token in the HTTP `Authorization` header, you can inform Heimdall to extract it from there by configuring this strategy as follows:

```.yaml
- header: Authorization
  strip_prefix: Bearer
```

### Query Parameter Strategy

This strategy can retrieve authentication data from the query of the request. Following properties are supported:

| Name              | Type     | Mandatory | Description                                             |
|-------------------|----------|-----------|---------------------------------------------------------|
| `query_parameter` | *string* | yes       | The name of the query parameter to use.                 |

**Example**

Imagine you want Heimdall to verify an access token used to protect your upstream service. If the client of your upstream application sends the access token in the query parameter named "access_token", you can inform Heimdall to extract it from there by configuring this strategy as follows:

```.yaml
- query_parameter: access_token
```

## Authentication Strategy

Authentication strategy is kind of abstract type, so you have to define which specific type to use. Each type has its own configuration options.

An AuthStrategy configuration entry must contain the following two properties:

* `type` - The type of the strategy. Available types are described in the following sections.
* `config` - The strategy specific configuration.

Available strategies are described in the following sections.

### API Key Strategy

This strategy can be used if your endpoint expects a specific api key be send in a header or a cookie.

`type` must be set to `api_key`. `config` supports the following properties:

| Name    | Type     | Mandatory | Description                                                    |
|---------|----------|-----------|----------------------------------------------------------------|
| `in`    | *enum*   | yes       | Where to put the api key. Can be either `header`, or `cookie`. |
| `name`  | *string* | yes       | The name of either the header or the cookie.                   |
| `value` | *string* | yes       | The value of the api key.                                      |

**Example**

The following snippet shows how to configure this strategy to send an api key in the `X-My-API-Key` HTTP header.

```.yaml
type: api_key
config:
  in: header
  name: X-My-API-Key
  value: super-duper-secret-key
```

### Basic Auth Strategy

This strategy can be used if your endpoint is protected by HTTP basic authentication and expects the HTTP `Authorization` header with required values.

`type` must be set to `basic_auth`. `config` supports the following properties:

| Name       | Type     | Mandatory | Description   |
|------------|----------|-----------|---------------|
| `user`     | *string* | yes       | The user-id.  |
| `password` | *string* | yes       | The password. |

**Example**

The following snippet shows how to configure this strategy with user set to "Alladin" and password set to "open sesame"

```.yaml
type: basic_auth
config:
  user: Alladin
  password: open sesame
```

### Client Credentials Strategy

This strategy implements the [OAuth2 Client Credentials Grant Flow](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) to obtain an access token expected by the endpoint. Heimdall caches the received access token.

`type` must be set to `client_credentials`. `config` supports the following properties:

| Name            | Type           | Mandatory | Description                                     |
|-----------------|----------------|-----------|-------------------------------------------------|
| `client_id`     | *string*       | yes       | The client identifier for Heimdall.             |
| `client_secret` | *string*       | yes       | The client secret for Heimdall.                 |
| `scopes`        | *string array* | no        | The scopes required for the access token.       |
| `token_url`     | *string*       | yes       | The token endpoint of the authorization server. |


**Example**

The following snippet shows how to configure this strategy

```.yaml
type: client_credentials
config:
  token_url: https://my-auth.provider/token
  client_id: foo
  client_secret: bar
  scopes:
    - baz
    - zap
```

## Duration

Duration is actually a string type, which adheres to the following pattern: `^[0-9]+(ns|us|ms|s|m|h)$`

So with `10s` you can define the duration of 10 seconds and with `2h` you can say 2 hours.

## Endpoint

The Endpoint type defines properties required for the communication with an endpoint.

| Name      | Type                                                                | Mandatory | Description                                                                              |
|-----------|---------------------------------------------------------------------|-----------|------------------------------------------------------------------------------------------|
| `url`     | *string*                                                            | yes       | the actual url of the endpoint                                                           |
| `method`  | *string*                                                            | no        | the HTTP method to use while communicating with the endpoint. If not set `POST` is used. |
| `retry`   | *[Retry]({{< ref "#retry" >}})*                                     | no        | what to do if the communication fails. If not configured, no retry attempts are done.    |
| `auth`    | *[Authentication Strategy]({{< ref "#authentication-strategy" >}})* | no        | authentication strategy to apply, if the endpoint requires authentication.               |
| `headers` | *Map of strings*                                                    | no        | HTTP headers to be send to the endpoint                                                  |

**Example**

```.yaml
endpoint:
  url: http://foo.bar
  method: GET
  retry:
    give_up_after: 5s
    max_delay: 1s
  auth:
    type: api_key
    config:
      name: foo
      value: bar
      in: cookie
  headers:
    X-My-First-Header: foobar
    X-My-Second-Header: barfoo
```

## Error Condition

This type supports definition of conditions, under which an error handler should execute its logic. Such conditions are required for all error handlers, but the default one. Each entry element in a condition is evaluated using boolean `and`.

| Name              | Type                                            | Mandatory | Description                                                                                                                                                    |
|-------------------|-------------------------------------------------|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `error`           | *[Error Type]({{< ref "#error-type" >}}) array* | yes       | A list with error types to match. Each entry is evaluated using a boolean `or` logic.                                                                          |
| `request_cidr`    | *string array*                                  | no        | A list with CIDR entries to match. Each entry is evaluated using a boolean `or` logic.                                                                         |
| `request_headers` | *string array map*                              | no        | A map with header names and the corresponding values to match. Each entry is evaluated using a boolean `or` logic. This holds also true for the header values. |

**Example 1**

This example shows in principle all possible combinations. The actual values and the amount of them will for sure differ in your particular case. However, for showing the idea, the complexity of this example is enough.

```yaml
error:
  - argument_error
  # OR
  - forbidden
# AND
request_cidr:
  - 192.168.0.0/16
  # OR
  - 10.0.0.0/8
# AND
request_headers:
  Accept:
    - text/html
    # OR
    - "*/*"
  # OR
  Content-Type:
    - application/json
```

This condition evaluates to true only if all parts of it (`error`, `request_cidr`, `request_headers`) evaluate to true. With
* `error` evaluates to true, if the encountered error was either `argument_error` or `forbidden`. 
* `request_cidr` evaluates to true, if the request came from an IP in either `192.168.0.0/16` or `10.0.0.0/8` range. And
* `request_headers` evaluates to true, if either the HTTP `Accept` header contains one of `text/html`, or `*/*`, or the HTTP `Contet-Type` header contains `application/json`. 

**Example 2**

This example is a very simple one, showing just the usage of the `error` attribute:

```yaml
error:
  - unauthorized
```

This condition evaluate to true, if the encountered error was `unauthorized`. 

## Error Type

Heimdall defines a couple of error types, which it uses to signal errors and which you can use while configuring your [Error Condition]({{< ref "#error-condition" >}})s.

Following types are available:

* `unauthorized` - used if an authenticator failed to verify authentication data available in the request. E.g. an authenticator was configured to verify a JWT and the signature of it was invalid. 
* `forbidden` - used if an authorizer failed to authorize the subject. E.g. an authorizer is configured to use a script to execute on the given subject and request context, but this script returned with an error.
* `internal_server_error` - used if Heimdall run into an internal error condition while processing the request. E.g. something went wrong while unmarshalling a JSON object, or if there was a configuration error, which couldn't be raised while loading a rule, etc. 
* `bad_argument` - used if the request does not contain required/expected data. E.g. if an authenticator could not find a cookie configured.

## Retry

Implements an exponential backoff strategy for endpoint communication. It increases the backoff exponentially by multiplying the `max_delay` with 2^(attempt count)

| Name            | Type                                  | Mandatory | Description                                                                                                    |
|-----------------|---------------------------------------|-----------|----------------------------------------------------------------------------------------------------------------|
| `give_up_after` | *[Duration]({{< ref "#duration" >}})* | no        | sets an upper bound on the maximum time to wait between two requests. Default to 0, which means no upper bound |
| `max_delay`     | *[Duration]({{< ref "#duration" >}})* | yes       | the initial backoff.                                                                                           |

**Example**

```.yaml
retry:
    give_up_after: 60s
    max_delay: 1s
```

In this example the backoff will be 1, 2, 4, 8, 16, 32, 60, ...

## Scopes Matcher

Scopes matcher is a configuration type allowing configuration of different strategies to match required scopes. In its simplest shape it can be just an array of strings (implemented by the [Exact]({{< ref "#exact">}})) scope mtcher. To cover many use cases, different strategies are available and described in the following sections.

Regardless of the strategy, each matcher can explicitly be configured and supports the following configuration properties:

* `matching_strategy` - the type of the mathing strategy.
* `values` - the list of scope patterns

### Exact

This the simplest matcher and is automatically selected, if just an array of strings is configured as shown in the following snippet:

```yaml
- foo
- bar
```

However, as written in the [Scopes Matcher]({{< ref "#scopes-matcher">}}) section, it can also explicitly be selected by setting `matching_strategy` to `exact` and defining the required scopes in the `values` property.

**Example**

The following two configurations are essentially the same:

```yaml
matching_strategy: exact
values:
  - foo
  - bar
```

```yaml
  - foo
  - bar
```

### Hierarchic

This matcher enables matching hierarchical scopes, which use `.` as separator. Imagine your system is organized that way, that it defines namespaces for different services like this:

* `my-service` being the top namespace
* `my-service.booking` - being the namespace of the booking service
* `my-service.orders` - being the namespace of the orders service
* `my-service.orders.partners` - being the namespace of the order service for partners and
* `my-service.orders.customers` - being the namespace of the order service for customers

Basically you've established an identity for each of your services (this is comparable to how [SPIFFE IDs](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#spiffe-id) are organized and also used for).

Now, imagine you use these namespaces as scope values to limit the usage of the issued tokens. In such situations the hierarchic scope matcher can become handy if you would like to assert any scope of the token must be in e.g. the `my-service` or the `my-service.orders` namespace.

This matcher can only be used by explicitly setting the `matching_strategy` to `hierarchic` and defining the required patterns in the `values` property.

**Example 1**

```yaml
matching_strategy: hierarchic
values:
  - my-service
```

This configuration will ensure all scopes withing the scope or scp claim are within the `my-service` namespace. So scope claim like

```json
{
  "scope": ["my-service.orders", "my-service.orders.customers"]
}
```

would match, but

```json
{
  "scope": ["not-my-service", "my-service.orders.customers"]
}
```

would not match.

### Wildcard

This matcher enables matching scopes using wildcards. It goes beyond the [Hierarchic]({{< ref "#hierarchic">}}) scope matcher by enabling usage of wildcards.

This matcher can only be used by explicitly setting the `matching_strategy` to `wildcard` and defining the required patterns in the `values` property.

## Session

This configuration type enables extraction of subject information from responses received by Heimdall from authentication services. Following properties are available.

| Name                      | Type   | Mandatory | Description                                                                                                                                              |
|---------------------------|--------|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `subject_id_from`         | string | yes       | A [GJSON Path](https://github.com/tidwall/gjson/blob/master/SYNTAX.md) pointing to the id of the subject in the JSON object                              |
| `subject_attributes_from` | string | no        | A [GJSON Path](https://github.com/tidwall/gjson/blob/master/SYNTAX.md) pointing to the attributes of the subject in the JSON object. Defaults to `@this` |

**Example 1**

This example shows how to extract the subject id from an [OAuth2 Introspection](https://tools.ietf.org/html/rfc7662) endpoint response and set the subject attributes to the entire response

```.yaml
subject_id_from: sub
subject_attributes_from: @this
```

Setting `subject_attributes_from` was actually not required, as `@this` would be set by default anyway.

**Example 2**

This example shows how to extract the subject id from an [Ory Kratos](https://www.ory.sh/docs/kratos/) "whoami" endpoint response and set the subject attributes to the entire response. `subject_attributes_from` is not configured, so default is used.

```.yaml
subject_id_from: identity.id
```