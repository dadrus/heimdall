---
title: "Metrics"
date: 2022-06-09T22:16:45+02:00
lastmod: 2022-06-09T22:16:45+02:00
draft: false
menu:
  docs:
    weight: 20
    parent: "Observability"
---

As of today, heimdall only supports [Prometheus](https://grafana.com/oss/prometheus/) as metrics backend, which is also enabled by default by exposing available metrics on `0.0.0.0:9000/metrics` endpoint.

## Configuration

Metrics configuration can be adjusted in the `prometheus` property, which lives in the `metrics` property of heimdall's configuration and supports following properties.

### Host

By making use of the `host` (*string*) property, you can specify the TCP/IP address on which heimdall should listen for connections from client applications. The entry `0.0.0.0` allows listening for all IPv4 addresses. `0.0.0.0` is also the default setting.

**Example**

In this example, we configure heimdall to allow only local TCP/IP “loopback” connections to be made.

```yaml
metrics:
  prometheus:
    host: 127.0.0.1
```

### Port

By making use of the `port` (*integer*) property, you can specify the TCP port the heimdall should listen on. Defaults to `9000`.

**Example**

In this example, we configure heimdall to listen on port `9999` for metrics requests.

```yaml
metrics:
  prometheus:
    port: 9999
```

### Metrics Path

By making use of the `metrics_path` (*string*) property, you can specify the path under which prometheus metrics information is made available. Defaults to `/metrics`.

**Example**

In this example, we configure heimdall expose metrics information behind `/prometheus` path.

```yaml
metrics:
  prometheus:
    metrics_path: /prometheus
```

