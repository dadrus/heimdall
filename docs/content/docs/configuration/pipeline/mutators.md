---
title: "Mutators"
date: 2022-06-09T18:57:16+02:00
lastmod: 2022-06-09T18:57:16+02:00
draft: true
toc: true
menu:
  docs:
    weight: 40
    parent: "Pipeline"
---

Mutators finalize the successful execution of the pipeline and transform the available information about the subject into a format expected, respectively required by the upstream service. This ranges from adding a query parameter, to a structured JWT in a specific header.

The following section describes the available mutator types in more detail.

## Mutator Types

### Noop

As the name implies, this mutator does nothing. As mutators are the last step in Heimdall's pipeline and transform available subject information into an object required by the upstream service, the usage of this mutator makes only sense in combination with the [Noop Authenticator]({{< ref "authenticators.md#noop">}}) for public APIs. This authenticator type also doesn't have any configuration options.

To enable the usage of this mutator, you have to set the `type` property to `noop`.

**Example**

```yaml
id: foo
type: noop
```

### Header

This mutator enables transformation of a subject into HTTP headers. 

To enable the usage of this mutator, you have to set the `type` property to `header`.

Configuration using the `config` property is mandatory. Following properties are available:

| Name      | Type         | Mandatory | Overridable | Description                                                                                          |
|-----------|--------------|-----------|-------------|------------------------------------------------------------------------------------------------------|
| `headers` | *string map* | yes       | yes         | Enables configuration of arbitrary headers with any values build from available subject information. |

**Example**

```yaml
id: foo
type: header
config:
  headers:
    - X-User-ID: {{ quote .ID }}
    - X-User-Email: {{ quote .Attributes["email"] }}
```

### Cookie

This mutator enables transformation of a subject into cookies.

To enable the usage of this mutator, you have to set the `type` property to `cookie`.

Configuration using the `config` property is mandatory. Following properties are available:

| Name      | Type         | Mandatory | Overridable | Description                                                                                          |
|-----------|--------------|-----------|-------------|------------------------------------------------------------------------------------------------------|
| `cookies` | *string map* | yes       | yes         | Enables configuration of arbitrary cookies with any values build from available subject information. |

**Example**

```yaml
id: foo
type: header
config:
  cookies:
    - X-User-ID: {{ quote .ID }}
    - X-User-Email: {{ quote .Attributes["email"] }}
```

### JWT

This mutator enables transformation of a subject into a bearer token in a [JWT](https://www.rfc-editor.org/rfc/rfc7519) format, which is made available to your upstream service in the HTTP `Authorization` header . In addition to setting the JWT specific claims, it allows setting custom claims as well. Your upstream service can then verify the signature of the JWT by making use of Heimdall's JWKS endpoint to retrieve the required public keys/certificates from.

To enable the usage of this mutator, you have to set the `type` property to `jwt`. The usage of this mutator type requires a Signer as well.

Configuration using the `config` property is optional. Following properties are available:

| Name     | Type                                                        | Mandatory | Overridable | Description                                                                                                                                                                                                      |
|----------|-------------------------------------------------------------|-----------|-------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `claims` | *string*                                                    | no        | yes         | Your template with custom claims, you would like to add to the JWT. See also [Templating]({{< ref "_index.md#templating" >}}).                                                                                   |
| `ttl`    | *[Duration]({{< ref "configuration_types.md#duration" >}})* | no        | yes         | Defines how long the JWT should be valid. Defaults to 5 minutes. Heimdall sets the `iat` and the `nbf` claims to the current system time. The value of the `exp` claim is then influenced by the `ttl` property. | 

The generated JWT is always cached until 5 seconds before its expiration. The cache key is calculated from the entire configuration of the mutator instance and the available information about the current subject.

**Example**

```yaml
id: jwt_mut
type: jwt
config:
  ttl: 5m
  claims: |
    {
      {{ $user_name := .Attributes.identity.user_name -}}
      "email": {{ quote .Attributes.identity.email }},
      "email_verified": {{ .Attributes.identity.email_verified }},
      {{ if $user_name -}}
        "name": {{ quote $user_name }}
      {{ else -}}
        "name": {{ quote $email }}
      {{ end -}}
    }
```
