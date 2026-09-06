# AGENTS.md

This file provides repository-specific guidance for AI coding agents working on Heimdall.

The rules in this file take precedence over generic coding-agent conventions when working in this repository.

## Core principles

### Security comes first

**Heimdall is security infrastructure. Every change must be reviewed for security implications, without exception.**

Heimdall participates directly in authentication, authorization, access-control decisions, identity propagation, request processing, and enforcement at trust boundaries.

A defect can result in unauthorized access, authentication bypass, privilege escalation, information disclosure, credential leakage, or incorrect policy enforcement.

Security therefore applies to every kind of change, including:

* feature work;
* bug fixes;
* refactoring;
* performance optimization;
* configuration;
* dependency updates;
* parsing and serialization;
* logging and error handling;
* tests;
* documentation;
* utility code.

Assume externally supplied data is attacker-controlled until trust has explicitly been established.

Preserve:

* trust boundaries;
* authentication and authorization guarantees;
* fail-closed behavior;
* confidentiality of credentials and security-sensitive information;
* isolation of request-specific state.

**Correctness and security take precedence over convenience, abstraction purity, allocation reduction, and performance.**

Never weaken a security control merely to simplify an implementation, make a test pass, or ease an integration.

### Preserve the project's design goals

When making changes, preserve:

* **Security** — maintain security guarantees and trust boundaries.
* **Performance** — avoid unnecessary work on request-processing paths.
* **Clear abstractions** — keep responsibilities and boundaries explicit.
* **Simplicity** — prefer understandable solutions over clever ones.
* **Secure defaults** — failures at security boundaries must not silently become successful decisions.

## Before making changes

Before modifying code:

1. Read the implementation in the affected package.
2. Read the corresponding tests.
3. Inspect adjacent code for established patterns.
4. Identify affected trust boundaries and security assumptions.
5. Consider malformed, ambiguous, unexpected, and malicious input.
6. Check whether related documentation, schemas, configuration, examples, or deployment artifacts are affected.

Prefer extending existing patterns over introducing another way to solve the same problem.

Keep changes focused. Avoid unrelated cleanup and refactoring.

## Repository map

Important areas include:

* `main.go` — application entry point.
* `cmd/` — CLI commands.
* `internal/app/` — application-level contracts and context.
* `internal/config/` — application configuration.
* `internal/pipeline/` — core request-processing abstractions.
* `internal/rules/` — rule matching, construction, repositories, and execution.
* `internal/rules/mechanisms/` — authentication, authorization, contextualization, finalization, and error handling.
* `internal/handler/` — proxy, decision, management, HTTP, and Envoy authorization adapters.
* `internal/keyregistry/` and `internal/secrets/` — key and secret handling.
* `internal/x/` — shared lower-level helpers.
* `schema/` — schemas exposed to users or tooling.
* `charts/heimdall/` — Helm chart and chart tests.
* `docs/content/docs/` — product and reference documentation.
* `docs/content/guides/` — task-oriented guides.
* `docs/openapi/` — OpenAPI documentation.
* `examples/` — example deployments and configurations.
* `examples/docker-compose/` — runnable Docker Compose quickstarts.
* `docker/` — container image definitions.
* `.github/ISSUE_TEMPLATE/` — issue templates.
* `.github/pull-request-template.md` — pull request template.

Security-sensitive behavior is not limited to security-named packages.

## Architecture

### Pipelines

`internal/pipeline` defines fundamental request-processing contracts and carries security-relevant state between steps.

Existing mechanism kinds include:

* authenticator;
* authorizer;
* contextualizer;
* finalizer;
* error handler.

Do not duplicate these concepts merely to avoid using existing abstractions.

Changes to pipeline interfaces are cross-cutting. Inspect implementations, mocks, rules, execution, and handlers before changing them.

Ensure changes cannot:

* lose or overwrite identity information;
* mix state from different requests;
* bypass required pipeline stages;
* incorrectly reuse previous results;
* turn fail-closed behavior into fail-open behavior.

### Rules and mechanisms

Concrete mechanisms belong under the corresponding area in `internal/rules/mechanisms`.

When adding or changing a mechanism:

* follow comparable existing implementations;
* preserve mechanism boundaries;
* reuse shared infrastructure;
* preserve validation and secure defaults;
* consider bypass and malformed-input scenarios;
* add positive, negative, and failure-path tests;
* update schemas, examples, and documentation where necessary.

Authentication and authorization mechanisms must not silently accept malformed, incomplete, ambiguous, or unverifiable input unless that behavior is explicitly part of their contract.

### Dependency injection

Heimdall uses Uber Fx.

Integrate new components through the existing module structure.

Do not:

* bypass dependency injection for convenience;
* introduce service-locator patterns;
* introduce global mutable dependencies.

Pay particular attention to component lifetime and mutable state. Request-, identity-, tenant-, or authorization-specific state must not leak across requests.

### Handlers and protocol adapters

Different adapters may represent the same logical HTTP request differently.

When changing request interpretation or decision behavior, inspect all affected adapters.

Do not assume behavior verified for one mode automatically applies to:

* proxy mode;
* HTTP decision APIs;
* Envoy external authorization;
* other supported integrations.

## Performance-sensitive code

Request handling and rule execution are hot paths.

**Prefer allocation-free implementations where practical, especially for code executed per request.**

Avoid allocations and runtime work that can reasonably be eliminated without harming correctness, security, or maintainability.

Prefer:

* reuse of existing representations;
* immutable precomputed data;
* initialization-time computation where appropriate;
* avoiding unnecessary intermediate slices, maps, strings, and wrappers;
* avoiding unnecessary string/byte conversions;
* typed code over reflection when practical.

Do not move initialization work into per-request code merely for implementation convenience.

Preserve existing allocation characteristics on hot paths where practical.

Do not introduce pooling solely to reduce allocations unless lifetime, concurrency, reset semantics, and security implications are well understood. Reused objects must never retain state from previous requests.

Do not perform speculative micro-optimizations that significantly reduce clarity.

**Never trade validation or security semantics for fewer allocations or better performance.**

When modifying caching:

* ensure cache keys contain every property relevant to the decision;
* prevent reuse across identities, tenants, rules, or contexts where invalid;
* consider expiration and invalidation;
* consider concurrent access;
* ensure cached security state cannot leak across requests.

## Security considerations

The following areas require particular care:

* authentication and authorization;
* rule matching and precedence;
* request targets and paths;
* URL parsing, escaping, decoding, and normalization;
* headers and forwarding information;
* credentials, tokens, keys, and secrets;
* proxy and trust boundaries;
* upstream request construction;
* configuration parsing;
* caching;
* logging and errors;
* concurrency and mutable state;
* serialization and protocol conversion.

This list is not exhaustive.

### Fail closed

Invalid, malformed, unverifiable, ambiguous, or incomplete security-relevant input should result in rejection unless explicitly documented otherwise.

Do not:

* convert security failures into success;
* ignore validation failures;
* fall back to less restrictive behavior;
* interpret missing security information as successful authorization.

### Trust boundaries

Validation of syntax does not establish trust.

Treat data from clients, proxies, gateways, external identity providers, remote services, credentials, and forwarded headers according to the trust model already established by the system.

Whenever information crosses a trust boundary, verify that the receiving component cannot interpret it with stronger privileges or different semantics than intended.

### URLs and paths

Request-target handling is an authorization boundary.

When working with URLs, paths, or matching, consider:

* raw vs. escaped vs. decoded forms;
* normalization;
* encoded path separators;
* dot segments;
* query strings;
* repeated encoding;
* duplicate separators;
* case sensitivity where relevant;
* differences between adapters.

The resource authorized by Heimdall must correspond to the resource ultimately processed downstream.

If two components can interpret the same request differently, treat that discrepancy as a potential security issue.

### Headers

Treat identity, routing, forwarding, and original-request headers as untrusted unless the architecture explicitly establishes trust.

Do not:

* trust client-controlled forwarding headers contrary to existing trust rules;
* allow clients to inject identity information Heimdall is expected to establish;
* preserve stale identity information when Heimdall should replace it;
* introduce ambiguous duplicate security-sensitive headers;
* expose sensitive values through logging or errors.

### Authentication and authorization

Authentication must not succeed on incomplete or unverifiable evidence.

Authorization must be based only on trusted, correctly interpreted information.

Consider, where relevant:

* missing or malformed credentials;
* unsupported formats or algorithms;
* invalid signatures;
* issuer and audience validation;
* expiration and validity windows;
* key rotation and key selection;
* duplicate credential sources;
* malformed or unexpected claims;
* rule precedence;
* default rules;
* conflicting rules;
* requester-controlled values.

A missing or failed authorization decision must never implicitly mean "allow".

### Secrets, errors, and logging

Never expose:

* passwords;
* access or refresh tokens;
* private keys;
* client secrets;
* signing material;
* resolved secret values;
* raw credentials.

This applies to logs, errors, tests, fixtures, documentation, issues, and pull requests.

Error messages should provide useful diagnostics without unnecessarily disclosing security-sensitive implementation details.

### Parsing, concurrency, and state

Parsing differences can become security vulnerabilities.

Ensure validation and execution operate on compatible representations.

Consider:

* duplicate fields;
* malformed and alternate encodings;
* size limits;
* unknown fields where relevant;
* differences between parser behavior and downstream interpretation.

Request-specific state must remain request-specific.

Concurrency, pooling, reuse, and caching must not allow identity or authorization state to leak between requests.

## Formatting and diff discipline

**Do not reformat existing code merely because a file is being modified.**

Preserve existing formatting outside the code that actually requires modification.

Do not:

* run repository-wide formatting as part of an unrelated change;
* reformat an entire touched file;
* change whitespace, wrapping, or alignment unrelated to the task;
* reorder existing code purely for style;
* apply personal or tool-specific formatting preferences to untouched code.

New or necessarily modified code should follow surrounding conventions and satisfy repository linting requirements.

If tooling reformats unrelated code automatically, revert those changes.

Always review the final diff for accidental formatting changes.

## Go conventions

Use the Go version declared in `go.mod`.

Follow existing package, naming, error-handling, and abstraction conventions.

For production code, prefer:

* small functions with clear responsibilities;
* explicit error handling;
* existing project types over parallel abstractions;
* interfaces at established boundaries;
* concrete types where abstraction adds no value.

Avoid:

* unnecessary exported APIs;
* global mutable state;
* generic helper packages that hide behavior;
* abstractions created for a single trivial use case;
* unrelated renaming or code movement.

The rules for production-code abstraction do **not** apply mechanically to tests.

## Tests

Tests favor **locality, readability, and self-description over DRYness**.

This is intentional.

### Keep tests self-contained

A reader should normally be able to understand a test without jumping through several helper functions or files.

Prefer:

* explicit setup;
* explicit expectations;
* explicit assertions;
* test data close to where it is used;
* some duplication when it improves readability.

Avoid:

* extracting setup merely to remove repetition;
* generic assertion helpers;
* builders that only make tests shorter;
* helpers that hide behavior important to the test;
* sharing helpers across unrelated test suites.

**Test helpers are the exception, not the default.**

Introduce a helper only when avoiding it would make the test substantially harder to understand or maintain.

When in doubt, keep the logic directly in the test.

### Prefer table-driven tests

Table-driven tests are the preferred style for multiple behavioral cases of the same function or method.

Use descriptive case names.

Before adding a new test function, find the existing tests for the behavior being changed.

If an appropriate table-driven test already exists:

* add new functionality as another case;
* add bug regressions as additional cases;
* preserve the existing structure.

Do not create a parallel test function when the new behavior naturally belongs in the existing test table.

For bug fixes, prefer:

1. add a reproducing case to the existing table;
2. verify it fails where practical;
3. fix the implementation;
4. verify the complete table passes.

### Security-sensitive tests

Security-sensitive changes must include more than happy-path coverage.

Consider, where applicable:

* missing and empty input;
* malformed input;
* duplicate input;
* invalid credentials;
* unsupported algorithms;
* manipulated claims;
* encoded and alternate representations;
* unexpected normalization;
* conflicting rules;
* untrusted forwarding information;
* cross-request leakage;
* cache-key collisions;
* concurrent execution.

For URL/path changes, consider encoded separators, dot segments, query strings, malformed input, repeated encoding, and differences between protocol adapters.

Regression tests should demonstrate that plausible bypass variants remain rejected.

### General test rules

* Keep tests deterministic.
* Prefer local fakes, fixtures, or mocks over external network dependencies.
* Do not weaken assertions merely to make a change pass.
* Do not remove test cases without understanding why they exist.
* Regenerate configured mocks through the repository's Mockery workflow instead of manually editing generated files.

## Development commands

Use the repository `Justfile` as the canonical command interface.

List available commands with:

```sh
just
```

During development, use focused tests where useful.

For substantial Go changes, run:

```sh
just test
just lint
```

Use:

```sh
just build
```

when changes can affect compilation, application composition, or CLI behavior.

For broader changes:

```sh
just test-all
```

For Helm changes:

```sh
just lint-helmchart
just test-chart
```

For OpenAPI changes:

```sh
just lint-api
```

For dependency changes:

```sh
just dependencies
just check-licenses
```

For Dockerfile changes:

```sh
just lint-dockerfile
```

Running tooling does not override the formatting rules above. Revert unrelated formatting changes.

## Documentation

Documentation is part of the product and must remain consistent with the implementation.

User-visible changes to behavior, configuration, APIs, mechanisms, rules, security properties, deployment, or operation normally require corresponding documentation updates.

Before modifying documentation:

* read the surrounding pages;
* read at least one comparable document;
* for new or substantially changed guides, read two or three similar existing guides.

Follow existing structure, terminology, tone, and AsciiDoc conventions. Do not impose a generic AI-generated documentation style.

### Information architecture

Use the existing organization:

* `docs/content/docs/concepts/` — mental models and architecture.
* `docs/content/docs/configuration/` — configuration reference.
* `docs/content/docs/mechanisms/` — mechanism reference.
* `docs/content/docs/rules/` — rules and matching.
* `docs/content/docs/services/` — exposed services.
* `docs/content/docs/operations/` — operational concerns.
* `docs/content/docs/getting_started/` — introductory end-to-end material.
* `docs/content/guides/` — concrete tasks and integrations.

Do not create a new page when the information belongs naturally in an existing one.

Prefer linking to canonical reference documentation over duplicating it.

### Match the documentation type

Concept documentation should explain mental models and relationships.

Reference documentation should describe exact semantics, including where relevant:

* mandatory vs. optional;
* defaults;
* accepted values;
* precedence and overriding;
* validation;
* failure behavior;
* interactions with other settings;
* security implications.

Guides should solve a concrete task and generally include:

1. intended outcome;
2. prerequisites;
3. required configuration;
4. explanation of non-obvious choices;
5. execution;
6. verification;
7. cleanup where applicable.

Do not turn guides into complete reference manuals.

### Writing style

Write for users of Heimdall, not for implementation authors.

Prefer direct, factual language.

Explain behavior and consequences instead of restating property names or Go types.

Avoid:

* generic introductions;
* marketing language;
* filler;
* unnecessary summaries;
* excessive headings;
* irrelevant implementation details;
* alternate terminology for existing Heimdall concepts.

Documentation accompanying a code change should describe the resulting behavior, not narrate the development history.

### AsciiDoc and examples

Follow the conventions of surrounding `.adoc` files for:

* front matter;
* headings;
* `:toc:`;
* `relref` links;
* source blocks;
* callouts;
* tables;
* admonitions.

Use typed source blocks such as `[source, yaml]`, `[source, bash]`, and `[source, json]`.

Use callouts for larger examples when non-obvious configuration choices need explanation.

Examples must reflect actual Heimdall behavior.

Do not invent configuration properties, defaults, flags, headers, responses, or semantics from memory.

Verify them against authoritative repository sources.

Prefer existing examples under `examples/` and `examples/docker-compose/` for integration and end-to-end documentation.

Commands intended for readers should be copy-pasteable where practical.

### Security in documentation

Documentation is part of Heimdall's security surface.

Examples should use secure defaults wherever reasonably possible.

If an insecure setting is required for local development:

* state its purpose;
* clearly limit its scope;
* state that it is not recommended for production;
* explain the concrete security consequence where useful.

Do not present disabling authentication, authorization, TLS validation, proof verification, replay protection, or another security control as a normal solution to an integration problem.

When configuration changes a trust boundary, explain what becomes trusted and which surrounding component is expected to enforce the corresponding security property.

Never include real credentials or secret material.

### Make guides verifiable

Guides should show how to verify the described setup.

For security-related guides, where relevant, show both:

* expected successful behavior;
* an important rejected or failure case.

A successful happy path alone is not sufficient evidence that security configuration is correct.

### Validate documentation

For substantial documentation changes, run:

```sh
just run-docs
```

and inspect the rendered result.

Verify navigation, headings, links, anchors, source blocks, callouts, tables, terminology, examples, and security-sensitive recommendations.

## Keep related artifacts consistent

When changing one area, inspect related artifacts.

| Change                                 | Also inspect                               |
| -------------------------------------- | ------------------------------------------ |
| Application configuration              | config code, examples, schemas, docs, Helm |
| Rule configuration                     | rule examples, schemas, docs               |
| Authentication/authorization mechanism | docs, examples, schemas, negative tests    |
| Public API                             | OpenAPI docs and API linting               |
| Helm behavior                          | values, templates, chart tests             |
| Go dependency                          | `go.mod`, `go.sum`, license checks         |
| Docker behavior                        | `docker/`                                  |
| CLI behavior                           | `cmd/`, docs, examples                     |
| User-visible behavior                  | relevant documentation                     |

Do not change an example or schema merely to make it accept behavior the implementation should reject.

## GitHub issues and pull requests

Repository templates are mandatory.

Do not replace them with generic AI-generated structures.

Before drafting an issue or pull request:

* read the current repository template;
* inspect a few comparable existing entries;
* use them as guidance for terminology, structure, and level of detail;
* keep descriptions concise;
* avoid filler and unverified claims.

### Feature requests

Use:

`.github/ISSUE_TEMPLATE/FEATURE-REQUEST.yaml`

Before drafting:

1. read the template;
2. inspect relevant open feature requests;
3. inspect older or closed examples where useful;
4. check for an existing issue covering the same request.

Describe primarily **what is needed and why**.

Do not turn a feature request into an implementation specification unless constraints are essential.

Consider security implications, trust assumptions, and attack-surface changes where relevant.

### Bug reports

Use:

`.github/ISSUE_TEMPLATE/BUG-REPORT.yaml`

Before drafting:

1. read the template;
2. inspect comparable open bug reports;
3. inspect closed reports where useful;
4. search for an existing report of the same problem.

Keep observed behavior, expected behavior, reproduction steps, environment, configuration, and relevant logs clearly separated.

When practical, base reproduction on an existing example under:

`examples/docker-compose/`

Prefer adapting an existing quickstart over inventing a standalone environment.

A reproduction should identify:

* the base example;
* required modifications;
* exact commands or requests;
* observed result;
* expected result.

Do not include sensitive information.

### Pull requests

Use:

`.github/pull-request-template.md`

Before drafting:

1. read the current template;
2. inspect recent human-authored pull requests;
3. prefer examples touching similar code where available.

Preserve the template structure.

Keep the description focused on:

* why the change exists;
* implementation decisions reviewers need to understand;
* material security considerations;
* concrete changes.

Do not:

* repeat the complete issue;
* narrate the development process;
* claim tests or documentation were completed when they were not;
* mark checklist entries without verifying them;
* invent related issues.

## Change discipline

Prefer the smallest change that solves the requested problem while preserving security properties and existing abstractions.

Do not:

* perform unrelated refactoring;
* reformat unrelated code;
* silently change public APIs or configuration semantics;
* remove validation without understanding it;
* weaken authentication or authorization behavior;
* weaken tests to obtain a green run;
* replace established project patterns merely because another approach is more familiar;
* change release metadata unless required.

For tests, avoiding duplication is **not** sufficient justification for introducing helpers or abstractions.

## Handling failures

When tests or linting fail:

1. determine whether the failure is related to the change;
2. fix regressions introduced by the change;
3. consider whether the failure reveals a security assumption affected by the change;
4. do not delete, skip, or weaken tests merely to obtain a green run;
5. do not call a failure pre-existing without evidence.

If a required check cannot be run, report that explicitly.

## Mandatory review before finishing

Review the complete diff before considering the task finished.

Verify at minimum:

### Security

* trust boundaries were not unintentionally weakened;
* attacker-controlled or malformed input cannot bypass validation;
* authentication and authorization remain fail-closed;
* the authorized resource matches the resource ultimately processed;
* request-specific identity or authorization state cannot leak across requests;
* caching, concurrency, pooling, and reuse remain correctly scoped;
* sensitive information cannot leak through logs, errors, tests, examples, docs, issues, or PRs;
* relevant negative and bypass cases are tested.

### Code and tests

* the change addresses only the requested behavior;
* unrelated formatting was not introduced;
* hot-path changes do not introduce avoidable per-request allocations;
* existing table-driven tests were extended where appropriate;
* unnecessary test helpers were not introduced;
* relevant tests and lint checks were run.

### Documentation and artifacts

* documentation, schemas, examples, APIs, and deployment artifacts remain consistent;
* documentation follows existing style and information architecture;
* security-sensitive examples remain safe.

### Issues and pull requests

When creating an issue or PR, verify that:

* the repository template was used;
* comparable existing entries were reviewed;
* the description is concise;
* all claims and checked items are true;
* bug reproduction uses an existing Docker Compose example where practical.

## Final response

When reporting completed work, state:

* what changed;
* important implementation decisions;
* relevant security considerations;
* tests and checks that were run and their results;
* checks that could not be run;
* remaining relevant risks or follow-up work.
