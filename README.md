# Heimdall
[![CI](https://github.com/dadrus/heimdall/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/dadrus/heimdall/actions/workflows/ci.yml)
[![Security-Scan](https://github.com/dadrus/heimdall/actions/workflows/security.yaml/badge.svg)](https://github.com/dadrus/heimdall/actions/workflows/security.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/7738/badge)](https://www.bestpractices.dev/projects/7738)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/dadrus/heimdall/badge)](https://securityscorecards.dev/viewer/?uri=github.com/dadrus/heimdall)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Go Report Card](https://goreportcard.com/badge/github.com/dadrus/heimdall)](https://goreportcard.com/report/github.com/dadrus/heimdall)
[![codecov](https://codecov.io/gh/dadrus/heimdall/branch/main/graph/badge.svg)](https://codecov.io/gh/dadrus/heimdall)
[![Docker](https://img.shields.io/badge/image-0.16.3-blue?logo=docker)](https://hub.docker.com/r/dadrus/heimdall)
[![Helm Chart](https://img.shields.io/badge/dynamic/yaml.svg?label=chart&url=https://dadrus.github.io/heimdall/charts/index.yaml&query=$.entries.heimdall[0].version&logo=helm&logoColor=white)](https://github.com/dadrus/heimdall/tree/main/charts/heimdall)
[![Discord](https://img.shields.io/discord/1100447190796742698?logo=discord&logoColor=white&label=community)](https://discord.gg/qQgg8xKuyb)

## Background

Heimdall is inspired by the Zero Trust idea and also by [Pomerium](https://www.pomerium.com/docs) and [Ory's OAthkeeper](https://www.ory.sh/docs/oathkeeper). Some experience with both and my inability to update the latter one to include the desired functionality and behavior was Heimdall's born hour. 

## What is heimdall

Heimdall authenticates and authorizes incoming HTTP (HTTP 1.x and HTTP 2.0) requests as well as enriches these with further contextual information and finally transforms resulting subject information into a format, required by the upstream services.

It can do so:

* Standalone as a proxy in front of your service or web server that rejects unauthorized requests and forwards authorized ones to your end points, or 
* Integrated into any other proxy, ingress controller or API gateway, like Kong, NGNIX, Envoy, Traefik, Contour, Ambassador and many more. Here that other proxy will forward the incoming request to heimdall and depending on its response either forward the original request, verified and updated by heimdall to your upstream service, or reject it with the information provided by heimdall.

In both cases it acts as a Policy Enforcement and to some degree a Policy Decision Point according to [NIST Zero Trust Architecture (SP 800-207)](https://doi.org/10.6028/NIST.SP.800-207)

## How does authentication, authorization and transformation work

The decision-making and transformation processes in Heimdall are governed by rules or respectively rule sets. These rule sets can be independently configured and managed by each upstream service. Heimdall dynamically loads these rules from a variety of sources, including:

* `RuleSet` kubernetes resources (a corresponding CRD is shipped with the helm chart)
* Cloud storages, like AWS S3, Google's GC, etc.
* Local file system
* Any HTTP endpoint

That way, these rule sets cannot only be managed centrally, but be deployed together with each particular upstream service as well without the need to restart or redeploy heimdall. Indeed, these rule sets are optional first class citizens of the upstream service and allow:

* Implementation of secure defaults. If no rule matches the incoming request, a default decision and transformation, if configured, is applied. This is the reason for "optional first class citizens" above.
* Configuration of as many authentication (e.g. OpenID Connect), authorization (e.g. via CEL expressions, or via OPA, or OpenFGA), contextualization (by e.g. communicating to some specific endpoint) and finalization mechanisms (e.g. creation of a JWT out of the available subject information), supported by heimdall, as required for the particular system. So, if your system requires integration with multiple authentication providers, or you want to migrate from one to another, it is just a matter of configuring them in heimdall.
* Reuse and combination of these mechanisms in as many rules as required for the particular system.
* Partial reconfiguration of a particular mechanism in a rule if required by the upstream service.
* Authentication mechanism fallbacks.
* Implementation of different decision process schemes by combining e.g. authentication mechanisms with error handlers to drive authentication mechanism specific error handling strategies.
* Execution of authorization and contextualization mechanisms in any order. That way, if the information about your subject, available from the authentication system, is not sufficient to make proper authorization decisions, you can let heimdall call other services to retrieve that additional information.
* Conditional execution of authorization, contextualization and finalization mechanisms is possible. E.g. if depending on the available information about the subject you would like heimdall to either block the request, or let the upstream return different representations of the requested resource.

## Beyond the functionality

Heimdall's main focus points beyond its functionality are:

* Performance - To achieve this, heimdall does use any http routing frameworks and does not load or convert data during execution whenever possible. This is also true for reflection use.
* Clear abstractions - To allow extensibility and even replacement of components without side effects.
* Simplicity - To allow better understanding of code to everybody, who would like to contribute.

## Where can I find more details

Head over to the [documentation](https://dadrus.github.io/heimdall/) for details or if you would like to give it a try.

## Current state

* Production-ready and already in use by multiple organizations worldwide.
* Code base is stable and well-tested. 
* Some features are still missing, and the development of these features might lead to breaking changes in future updates.

For information on the currently supported functionality, please refer to the [Release descriptions](https://github.com/dadrus/heimdall/releases). Planned features can be found in the defined [Milestones](https://github.com/dadrus/heimdall/milestones).


## If you ...

* ... like the project - please give it a :star:
* ... miss something, or found a bug, [file a ticket](https://github.com/dadrus/heimdall/issues). You are also very welcome to [contribute](CONTRIBUTING.md) :wink:
* ... would like to support, reach out to me via [Discord](https://discord.gg/qQgg8xKuyb)
* ... need help, head over to [Discord](https://discord.gg/qQgg8xKuyb) as well
