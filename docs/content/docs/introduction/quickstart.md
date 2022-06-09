---
title: "Quickstart"
date: 2022-06-08T20:43:27+02:00
lastmod: 2022-06-08T20:43:27+02:00
description: ""
lead: ""
draft: true
images: []
weight: 999
toc: true
menu:
  main:
    weight: 999
    parent: "get_started"
---

# Quick Start

> :warning:&ensp; This functionality is not available right now. What you can see below is just the idea.


In this quick-start document we'll use a fully functional environment with heimdall using Docker. To make you understand, what you're doing, the used configuration and all the steps will be explained. To gain more in-depth understanding about the available configuration options, please head over to the [Configuration]({{ site.baseurl }}{% link configuration/configuration.md %}) chapter.

## Prerequisite

* [git](https://git-scm.com/)
* [Docker](https://docs.docker.com/install/) and [docker-compose](https://docs.docker.com/compose/install/)

## Download
Retrieve the latest copy of heimdall source code by cloning the git repository

```bash
$ git clone git@github.com:dadrus/heimdall.git
```

## Explore

Navigate to the `examples` directory of the repository.

```bash
$ cd heimdall/examples
```

Here you'll find the following directory structure:

TODO

## Run

Now that you know what to expect, start the environment using `docker-compose` within the `examples` directory of the repository

```bash
$ docker-compose up
```

## Use

Open your browser and navigate to `127.0.0.1:9090`. You should now be able to see a page, like shown below, displaying different scenarios you can try out.



