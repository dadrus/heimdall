---
title: "Logging"
date: 2022-06-09T18:56:07+02:00
lastmod: 2022-06-09T18:56:07+02:00
draft: false
menu:
  docs:
    weight: 10
    parent: "Observability"
---

Heimdall logs concern everything that happens to Heimdall itself (startup, configuration, events, shutdown, and so on). Logs are written to stdout by default in text format.

## Configuration

Logging configuration can be adjusted in the `log` property of heimdall's configuration and supports following properties.

### Format

By default, logs are written in text format, which can also be changed by using the `format` (*string*) option. Following formats are supported:

* `text` - The default one.
* `gelf` - A JSON format more or less adhering to [GELF](https://docs.graylog.org/v1/docs/gelf)

**Example**

Set logging to GELF format

```yaml
log:
  format: gelf
```

### Log Level

By default, the level is set to `error`. Log level can be set by using the `level` (*string*) option, with following log levels available: `debug`, `info`, `warn`, `error`, `fatal`, `panic` and `disabled`. The last one effectively disables logging. You usually do not want to do this.

**Example**

Set log level to `debug`

```yaml
log:
  level: debug
```

