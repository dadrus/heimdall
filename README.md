# Heimdall
[![CI](https://github.com/dadrus/heimdall/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/dadrus/heimdall/actions/workflows/ci.yml)
[![Security-Scan](https://github.com/dadrus/heimdall/actions/workflows/trivy.yaml/badge.svg)](https://github.com/dadrus/heimdall/actions/workflows/trivy.yml)
[![codecov](https://codecov.io/gh/dadrus/heimdall/branch/main/graph/badge.svg)](https://codecov.io/gh/dadrus/heimdall)
[![Go Report Card](https://goreportcard.com/badge/github.com/dadrus/heimdall)](https://goreportcard.com/report/github.com/dadrus/heimdall) 
[![License](https://img.shields.io/github/license/dadrus/heimdall)](https://github.com/dadrus/heimdall/blob/master/LICENSE)
[![Docker](https://img.shields.io/docker/v/dadrus/heimdall?color=lightblue&label=docker)](https://hub.docker.com/repository/docker/dadrus/heimdall)

## Background

Heimdall is inspired by the ZeroTrust idea and also by [Ory's OAthkeeper](https://www.ory.sh/docs/oathkeeper). Some experience with the latter and my inability to update it to include the desired functionality and behavior was Heimdall's born hour. 

## Heimdall's Promise

Heimdall authenticates and authorizes incoming HTTP requests as well as enriches these with further contextual information and finally transforms resulting subject information into a format, required by the upstream services. And all of that can be controlled by each and every backend service individually.

It is supposed to be used either as 
* a **Reverse Proxy** (not yet implemented) in front of your upstream API or web server that rejects unauthorized requests and forwards authorized ones to your end points, or as 
* a **Decision API**, which integrates with your API Gateway (Kong, NGNIX, Envoy, Traefik, etc) and then acts as a Policy Decision Point.

## Beyond the Functionality

Heimdall's main focus points beyond its functionality are:
* Performance - To achieve this, Heimdall makes use of [Fiber](https://gofiber.io/) and does not load or convert data during execution whenever possible. This is also true for reflection use.
* Clear abstractions - To allow extensibility and even replacement components if required, like e.g. of the currently used HTTP engine, and this without any side effects.
* Simplicity - To allow better understanding of code to everybody, who would like to contribute.

## Current State

The current implementation is an alpha version. That means it does not solve all the problems heimdall aims to solve. With other words a lot of functionality is missing. In addition, alpha version means, there will be breaking changes (configuration-wise). Nevertheless, the code base is stable and pretty good tested. Functionality already supported can be found in the current [Release description](https://github.com/dadrus/heimdall/releases/latest). Planned features can be found in the defined [Milestones](https://github.com/dadrus/heimdall/milestones).

If you like to give it a try, checkout out the [documentation](https://dadrus.github.io/heimdall/docs/welcome/).
