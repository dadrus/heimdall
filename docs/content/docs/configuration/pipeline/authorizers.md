---
title: "Authorizers"
date: 2022-06-09T18:57:03+02:00
lastmod: 2022-06-09T18:57:03+02:00
draft: true
toc: true
menu:
  docs:
    weight: 20
    parent: "Pipeline"
---

Authorizers ensure that the subject obtained via an authenticator step has the required permissions to submit the given HTTP request and thus to execute the corresponding logic in the upstream service. E.g. a specific endpoint of the upstream service might only be accessible to a "user" from the "admin" group, or to an HTTP request if a specific HTTP header is set.

The following section describes the available authorizer types in more detail.

## Authorizer Types

### Allow

As the name implies, this authorizer allows any request passing through. This authorizer type also doesn't have any configuration options.

To enable the usage of this authorizer, you have to set the `type` property to `allow`.

**Example**

```yaml
id: foo
type: allow
```

### Deny

As the name implies, this authorizer denies any request (on HTTP response code level this is then mapped to `Forbidden`). It basically stops the successful execution of the pipeline resulting in the execution of the error handlers. This authorizer type doesn't have any configuration options.

To enable the usage of this authorizer, you have to set the `type` property to `deny`.

**Example**

```yaml
id: foo
type: deny
```

### Local

This authorizer allows definition of authorization requirements based on information available about the authenticated subject, as well as the actual request by using [ECMAScript 5.1(+)](https://262.ecma-international.org/5.1/). The script is expected to either return `false` or raise an error if authorization fails. In such cases this authorizer denies the request. So, the successful execution of the pipeline stops, resulting in the execution of the error handlers. Otherwise, the authorizer assumes, the script allowed the request. 

If the script makes use of `raise` the corresponding message will be logged as reason for the failed authorization, otherwise a generic "authorization failed" will be logged.

To enable the usage of this authorizer, you have to set the `type` property to `local`.

Configuration using the `config` property is mandatory. Following properties are available:

| Name       | Type     | Mandatory | Overridable | Description                                              |
|------------|----------|-----------|-------------|----------------------------------------------------------|
| `script`   | *string* | yes       | yes         | ECMAScript wich executes the actual authorization logic. |

**Example:**

```yaml
id: foo
type: local
config:
  script: |
    if (heimdall.subject.Attributes["group"] !== "admin") {
      raise("user not in admin group")
    }
```

### Remote

This authorizer allows communication with other systems, like [Open Policy Agent](https://www.openpolicyagent.org/), [Ory Keto](https://www.ory.sh/docs/keto/), etc. for the actual authorization purpose. If the used endpoint answers with a not 2xx HTTP response code, this authorizer assumes, the authorization has failed and denies the request. So, the successful execution of the pipeline stops, resulting in the execution of the error handlers. Otherwise, the authorizer assumes, the request has been authorized. 

If your authorization system provides a payload in the response, Heimdall inspects the `Content-Type` header to prepare the payload for further usage, e.g. in a [Local]({{< relref "#local" >}}) authorizer. It can however deal only with a content type, which either ends with `json` or which is `application/x-www-form-urlencoded`. In these two cases, the payload is decoded and made available as map in the `.Attributes` of the subject. Otherwise, the payload is treated as string and made also available in the `.Attributes` property of the subject. To avoid overwriting of existing attributes, this object is however not available on the top level, but under a key named by the `id` of the authorizer (See also the example below).

To enable the usage of this authorizer, you have to set the `type` property to `remote`.

Configuration using the `config` property is mandatory. Following properties are available:

| Name                                   | Type                                                           | Mandatory | Overridable | Description                                                                                                                                                                                                                                                                                                                                                                             |
|----------------------------------------|----------------------------------------------------------------|-----------|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `endpoint`                             | *[Endpoint]({{< relref "configuration_types.md#endpoint">}})*  | yes       | no          | The API endpoint of your authorization system. At least the `url` must be configured. By default this authorizer will use HTTP `POST` to send the rendered payload to this endpoint. You can override this behavior by configuring `method` as well. Depending on the API requirements of your authorization system, you might need to configure further properties, like headers, etc. |
| `payload`                              | *string*                                                       | yes       | yes         | Your template with definitions required to communicate to the authorization endpoint. See also [Templating]({{< relref "_index.md#templating" >}}).                                                                                                                                                                                                                                     |
| `forward_response_headers_to_upstream` | *string array*                                                 | no        | yes         | Enables forwarding of any headers from the authorization endpoint response to the upstream service.                                                                                                                                                                                                                                                                                     |
| `cache_ttl`                            | *[Duration]({{< relref "configuration_types.md#duration" >}})* | no        | yes         | Allows caching of the authorization endpoint responses. Defaults to 0s, which means no caching. The cache key is calculated from the entire configuration of the authorizer instance and the available information about the current subject.                                                                                                                                           |

**Example:**

Here the remote authorizer is configured to communicate with [Open Policy Agent](https://www.openpolicyagent.org/). Since OPA expects the query to be formatted as JSON, the corresponding `Content-Type` header is set. Since the responses are JSON objects as well, the `Accept` header is also provided. In addition, this examples uses the `basic_auth` auth type to authenticate against the endpoint.

```yaml
id: foo
type: remote
config:
  endpoint:
    url: https://opa.local/v1/data/myapi/policy/allow
    headers:
      Content-Type: json
      Accept: json
    auth:
      type: basic_auth
      config:
        user: MyOpaUser
        password: SuperSecretPassword
  payload: |
    { "input": { "user": {{ quote .ID }}, "access": "write" } }
```

Since an OPA response could look like `{ "result": true }` or `{ "result": false }`, which obviously needs further evaluation, Heimdall makes it available under `.Attributes["foo"]` as a map, with `"foo"` being the id of the authorizer in this example. 