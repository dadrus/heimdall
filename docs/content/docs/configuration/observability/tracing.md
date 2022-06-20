---
title: "Tracing"
date: 2022-06-09T18:56:12+02:00
draft: false
menu:
  docs:
    weight: 30
    parent: "Observability"
---

Heimdall allows visualization of call flows in your infrastructure. It does this by using [OpenTracing](https://opentracing.io/), an open standard designed for distributed tracing.

Following tracing backends are currently supported:

* [Jaeger](https://www.jaegertracing.io/)
* [Instana](https://www.instana.com/)

## Configuration

By default, tracing is disabled, but can be configured in the `tracing` property of heimdall's configuration and supports following properties.

### Service Name

By setting the `service_name` (*string*) property, you can adjust the service name, appearing for Heimdall for your tracing backend. Defaults to `heimdall`. You can also override this value by making use of tracer specific configuration via environment variables.

**Example**

Here we are setting the service name, appearing for Heimdall for your tracing backend to `foobar`.

```yaml
tracing:
  service_name: foobar
```

### Provider

By making use of the `provider` (*string*) property, you can configure heimdall to enable tracing and use one of the supported tracing providers:

* `jaeger` - to use [Jaeger](https://www.jaegertracing.io/)
* `instana` - to use [Instana](https://www.instana.com/)

Further configuration of the tracer happens with tracer specific environment variables. If you don't do this, Heimdall makes use of tracer specific defaults. Head over to the configuration documentation of the supported tracing system, you want to use, for more details.

**Example**

Here we're enabling tracing with Jaeger.

```yaml
tracing:
  provider: jaeger
```

By default, Jaeger client assumes the agent is running on the same host. You can however, as mentioned above, change it by making use of `JAEGER_AGENT_HOST` environment variable.

