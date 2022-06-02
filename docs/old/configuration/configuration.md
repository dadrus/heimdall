---
layout: default
title: Configuration
nav_order: 3
has_children: true
---

# Configuration

The configuration of heimdall can be done either using environment variables or a config file. Latter can be passed to heimdall using the `--config /path/to/config.yaml` or the shorter `-c /path/to/config.yaml` flag. As of today only YAML format is supported. 

The documents listed below, document the available options for the implemented modes of operations, for the pipeline mechanisms and for the rules. If you need a full reference with all possible configuration values, please head over to [Reference]({{ site.baseurl }}{% link reference/reference.md %}).