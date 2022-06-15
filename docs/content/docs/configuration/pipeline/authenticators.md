---
title: "Authenticators"
date: 2022-06-09T18:56:56+02:00
lastmod: 2022-06-09T18:56:56+02:00
draft: true
menu:
  docs:
    weight: 10
    parent: "Pipeline"
---

Authenticators inspect HTTP requests, like the presence of a specific cookie, which represents the authentication object of the subject with the service and execute logic required to verify the authentication status and obtain information about that subject. A subject, could be a user who tries to use particular functionality of the upstream service, a machine (if you have machine-2-machine interaction), or something different. Authenticators ensure the subject has already been authenticated and the information available about it is valid.

## General Configuration

Before being able to use authenticators in a rule, the required ones must be configured:

```yaml
pipeline:
  authenticators:
    <list of authenticators>
```

Each authenticator configuration entry must contain at least the following properties:

* `id` - The unique identifier of an authenticator. Identifiers are used to reference the required authenticator from a rule. You can choose whatever identifier, you want. It is just a name. It must however be unique across all defined authenticators in the pipeline.
* `type` - The type of authenticator. This is used to select the required authenticator type. Available types are described in the next section.

Depending on authenticator type, there can be an additional `config` property for, as the name implies the definition of authenticator's specific configuration. Every authenticator type can be defined as many times as needed in the pipeline definition. However, for those, which don't have a configuration, it doesn't really make sense, as all of them would behave the same way.

So your authenticator definitions could look like this:

```yaml
pipeline:
  authenticators:
    - id: foo
      type: bar
    - id: baz
      type: bla
      config:
        bla: bar
    - id: zab
      type: bar
    - id: oof
      type: bla
      config:
        bar: bla
```

The above pipeline configures two instances of an imaginary authenticator of type `bar` available via ids `foo` and `zab`, as well as two instances of an imaginary authenticator of type `bla` available via ids `baz` and `oof`. The `baz` and `oof` authenticators are different, as they are configured differently, but `foo` and `zab` authenticators do not have a configuration, so they behave the same way and there is actually no need to define two instances of them.

## Authenticator Types

### Noop

As the name implies, this authenticator does nothing. It tells Heimdall to bypass the authentication. This is the only one authenticator type, which does not create a subject object on a successful execution, which is required by the most other pipeline handlers. This authenticator type also doesn't have any configuration options.

To enable the usage of this authenticator, you have to set the `type` property to `noop`. 

**Example**

```yaml
id: foo
type: noop
```

### Unauthorized

This authenticator tells Heimdall to reject all requests as unauthorized. It basically stops the successful execution of the pipeline resulting in the execution of the error handlers. This authenticator type doesn't have any configuration options.

To enable the usage of this authenticator, you have to set the `type` property to `unauthorized`. 

**Example:**

```yaml
id: foo
type: unauthorized
```

### Anonymous

This authenticator just creates a subject object and sets its id to `anonymous` without doing anything else. You can overwrite the value of subject's id by using the optional `config` property.

To enable the usage of this authenticator, you have to set the `type` property to `anonymous`. 

Configuration using the `config` property is optional. Following properties are available:

| Name      | Type     | Description                                                             |
|-----------|----------|-------------------------------------------------------------------------|
| `subject` | *string* | Enables setting the id of the created subject object to a custom value. |

**Example:**

```yaml
id: foo
type: anonymous
config:
  subject: anon
```

### Basic Auth

This authenticator verifies the provided credentials according to the HTTP "Basic" authentication scheme, described in [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617). This authenticator does not challenge the authentication, it only verifies the provided credentials and sets the subject id to the configured value if the authentications succeeds. Otherwise, it raises an error, which results in the execution of the configured error handlers. The "WWW Authenticate" error handler can then for example be used if the corresponding challenge is required.

To enable the usage of this authenticator, you have to set the `type` property to `basic_auth`.

Configuration using the `config` property is mandatory. Following properties are available:

| Name       | Type     | Description                                               |
|------------|----------|-----------------------------------------------------------|
| `user_id`  | *string* | The identifier of the subject to be verified (mandatory). |
| `password` | *string* | The password of the subject to be verified (mandatory).   |

**Example:**

```yaml
id: foo
type: basic_auth
config:
  user_id: bar
  password: baz
```

### Generic

This authenticator is kind of a swiss knife and can do a lot depending on the given configuration. It verifies the authentication status of the subject by making use of values available in the cookies, headers, or query parameters of the HTTP request and communicating with the actual authentication system to perform the actual verification on the one hand and to get the information about subject on the other hand. There is however one limitation: it can only deal with JSON responses.

To enable the usage of this authenticator, you have to set the `type` property to `generic`.

Configuration using the `config` property is mandatory. Following properties are available:

| Name                         | Type                                                                                            | Mandatory | Description                                                                                                                                                                                                                                                                                                                                                                           |
|------------------------------|-------------------------------------------------------------------------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `identity_info_endpoint`     | *[Endpoint]({{< ref "configuration_types.md#endpoint">}})*                                      | yes       | The endpoint to communicate to for the actual subject authentication status verification purpose. At least the `url` must be configured. If you don't configure `method`, HTTP `POST` will be used. The `Accept` header is set to `application/json` by default. You can overwrite these setting however if required. Don't forget - this authenticator supports only JSON responses. |
| `authentication_data_source` | *[Authentication Data Source]({{< ref "configuration_types.md#authentication-data-source" >}})* | yes       | Where to extract the authentication data from the request. This authenticator will use the matched authentication data source as is while sending it to the `identity_info_endpoint`. If you configure to strip a prefix (if header is defined, this will most probably not work)                                                                                                     |
| `session`                    | *[Session]({{< ref "configuration_types.md#session" >}})*                                       | yes       | Where to extract the subject id from the identity info endpoint response, as well as which attributes to use.                                                                                                                                                                                                                                                                         |
| `cache_ttl`                  | *[Duration]({{< ref "configuration_types.md#duration" >}})*                                     | no        | How long to cache the response. If not set, response caching if disabled.                                                                                                                                                                                                                                                                                                             |

**Example 1**

This example shows how to configure this authenticator to work with an authentication system, which issues a cookie upon successful user authentication to maintain the authentication state. To reduce the communication overhead, it also makes use of `cache_ttl` to cache the response for 5 minutes. 

```yaml
id: session_cookie
type: generic
config:
  identity_info_endpoint:
    url: http://my-auth.system/sessions/whoami
  authentication_data_source:
    - cookie: my_session
  session:
    subject_id_from: "identity.id"
  cache_ttl: 5m
```

**Example 2**

This example shows how to configure this authenticator to work with an authentication system, which issues a Bearer token upon successful user authentication to maintain the authentication state. To reduce the communication overhead, it also makes use of `cache_ttl` to cache the response for 5 minutes. In this example we configure the handler to use the `GET` method instead of the default `POST` for sending the bearer token to the authentication system for verification purposes and also to authenticate using HTTP basic auth schema. According to the below configuration, the Bearer token is located in the `X-Custom-Bearer-Token` header, which as also used as is while calling the `http://my-auth.system/introspect` endpoint.

```yaml
id: bearer_token
type: generic
config:
  identity_info_endpoint:
    url: http://my-auth.system/introspect
    method: GET
    auth:
      type: basic_auth
      config:
        user: Heimdall
        password: super-secure
  authentication_data_source:
    - header: X-Custom-Bearer-Token
  session:
    subject_id_from: "sub"
  cache_ttl: 5m
```

Usually, Bearer tokens are issued by an OAuth2 auth provider and there is a need to verify not only the validity of such, but also a couple of claims. This can be achieved by a "Local Authorizer", but there is also a special purpose [OAuth2 Introspection]({{< ref "#oauth2-introspection">}}) authenticator type, which supports asserting all security relevant claims in just one place.

### OAuth2 Introspection

This authenticator handles requests that have Bearer token in e.g. the HTTP Authorization header (`Authorization: Bearer <token>`), in a different header or a query parameter. It then uses [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662) endpoint to check if the token is valid. The validation includes at least the verification of the status and the time validity. That is if the token is still active and whether it has been issued in an acceptable time frame. Latter can be adjusted by specifying a leeway. All other validation options can and should be configured.

To enable the usage of this authenticator, you have to set the `type` property to `oauth2_introspection`.

Configuration using the `config` property is mandatory. Following properties are available:

| Name                     | Type                                                            | Mandatory | Description                                                                                                                                                                                                                                                                                                                                                                                |
|--------------------------|-----------------------------------------------------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `introspection_endpoint` | *[Endpoint]({{< ref "configuration_types.md#endpoint">}})*      | yes       | The introspection endpoint of the OAuth2 authorization provider. At least the `url` must be configured. There is no need to define the `method` property or setting the `Content-Type` or the `Accept` header. These are set by default to the values required by the [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662) RFC. You can however overwrite these. |
| `assertions`             | *[Assertions]({{< ref "configuration_types.md#assertions" >}})* | yes       | Configures the required claim assertions.                                                                                                                                                                                                                                                                                                                                                  |
| `session`                | *[Session]({{< ref "configuration_types.md#session" >}})*       | no        | Where to extract the subject id from the introspection endpoint response, as well as which attributes to use. If not configured `sub` is used to extract the subject id and all attributes from the introspection endpoint response are made available as attributes of the subject.                                                                                                       |
| `cache_ttl`              | *[Duration]({{< ref "configuration_types.md#duration" >}})*     | no        | How long to cache the response. If not set, caching of the introspection response is based on the available token expiration information. To disable caching, set it to `0s`. If you set the ttl to a custom value > 0, the expiration time (if available) of the token will be considered.                                                                                                |

**Example**

Here a minimal possible configuration

```yaml
id: at_opaque
type: oauth2_introspection
config:
  introspection_endpoint:
    url: http://hydra:4445/oauth2/introspect
  assertions:
    issuers:
      - http://127.0.0.1:4444/
```

### JWT

As the [OAuth2 Introspection]({{< ref "#oauth2-introspection">}}) authenticator, this authenticator handles requests that have a Bearer Token in the `Authorization` header, in a different header or a query parameter as well. Unlike the OAuth2 Introspection authenticator it expects the token to be a JSON Web Token (JWT) and verifies it according [RFC 7519, Section 7.2](https://www.rfc-editor.org/rfc/rfc7519#section-7.2). It does however not support encrypted payloads and nested JWTs. In addition to this, validation includes the verification of the time validity. Latter can be adjusted by specifying a leeway. All other validation options can and should be configured.

To enable the usage of this authenticator, you have to set the `type` property to `jwt`.

Configuration using the `config` property is mandatory. Following properties are available:

| Name          | Type                                                                                            | Mandatory | Description                                                                                                                                                                                                                                                                                                            |
|---------------|-------------------------------------------------------------------------------------------------|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| jwks_endpoint | *[Endpoint]({{< ref "configuration_types.md#endpoint">}})*                                      | yes       | The JWKS endpoint, this authenticator retrieves the key material in a format specified in [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) from for JWT signature verification purposes. The `url` must be configured. By default `method` is set to `GET` and the HTTP `Accept` header to `application/json` |
| jwt_from      | *[Authentication Data Source]({{< ref "configuration_types.md#authentication-data-source" >}})* | no        | Where to get the access token from. If not set, this authenticator tries to retrieve it from the `Authorization` header and the `access_token` query paramter.                                                                                                                                                         |
| assertions    | *[Assertions]({{< ref "configuration_types.md#assertions" >}})*                                 | yes       | Configures the required claim assertions.                                                                                                                                                                                                                                                                              |
| session       | *[Session]({{< ref "configuration_types.md#session" >}})*                                       | no        | Where to extract the subject id from the JWT, as well as which attributes to use. If not configured `sub` is used to extract the subject id and all attributes from the JWT payload are made available as attributes of the subject.                                                                                   |
| cache_ttl     | *[Duration]({{< ref "configuration_types.md#duration" >}})*                                     | no        | How long to cache the key from the JWKS response, which was used for signature verification purposes. If not set, Heimdall will cache this key for 10 minutes and not call JWKS endpoint again if the same `kid` is referenced in an JWT and same JWKS endpoint is used.                                               |

**Example**

Here a minimal possible configuration

```yaml
id: at_jwt
type: jwt
config:
  jwks_endpoint:
    url: http://hydra:4444/.well-known/jwks.json
  assertions:
    issuers:
      - http://127.0.0.1:4444/
```
