This file provides repository-specific guidance for AI coding agents working on Heimdall. It defines how to work on the project, not its current internal architecture.

## Project context

Heimdall is an identity-aware proxy and authorization decision service with multiple operating modes and protocol integrations. It is security infrastructure: **every change must be reviewed for security implications, without exception.**

Use the documentation and applicable specifications to establish intended behavior, and the implementation and tests to establish actual behavior. Investigate discrepancies rather than assuming either is correct.

**Correctness and security take precedence over convenience, abstraction purity, allocation reduction, and performance.**

## Scope and design

- Before editing, read the relevant source, tests, `README.md`, `go.mod`, and applicable documentation.
- Understand the requested behavior and, when changing existing behavior, compare the branch with `main`. Distinguish branch-introduced regressions from pre-existing issues. For release-specific changes, also inspect the relevant release baseline.
- Before changing behavior, trace the relevant data and error flow from its entry point to its final consumer. Inspect actual callers and implementations; identify transformations, fallbacks, trust boundaries, component responsibilities, and error propagation.
- When changing shared behavior, inspect affected operating modes, protocol adapters, and documented proxy integrations. Do not assume that a constructed request is reachable through a supported integration.
- Make the smallest coherent change. Do not include unrelated bug fixes, refactorings, dependency updates, or performance work; report those separately.
- For analysis-only requests, do not edit files or create patches unless asked.
- Follow existing naming, formatting, file organization, error handling, option, and configuration patterns.
- Apply SOLID pragmatically: keep responsibilities clear and abstractions justified by actual needs. Prefer readable, straightforward code (KISS before DRY); reuse existing mechanisms rather than introducing speculative interfaces or helpers.
- Keep validation close to the code responsible for the corresponding behavior.
- Separate static from context-dependent validation, and avoid redundant checks across layers. Checks at trust boundaries and checks of component invariants may coexist when they serve different purposes.
- Enforce security invariants in the components responsible for them. Do not rely exclusively on optional or replaceable middleware to make an otherwise unsafe component safe.
- Preserve public API and configuration compatibility unless explicitly asked otherwise, including option behavior, defaults, error contracts, response semantics, and serialized representations. If a security or correctness fix necessarily changes these, assess, document, and test the compatibility impact.
- Preserve existing pipeline contracts.
- Use the established Uber Fx dependency injection; do not introduce service locators or global mutable dependencies.
- Before changing an interface, inspect its implementations, consumers, mocks, and application composition.
- Do not change `go.mod` or `go.sum` merely to accommodate a local environment.
- Follow [CONTRIBUTING.md](./CONTRIBUTING.md) for the development workflow, standard checks, documentation, and pull-request conventions.

## Security and protocol compliance

- Check protocol-related changes against the relevant RFC text, not only existing tests or behavior on `main`. Explain consequential design decisions in terms of the applicable requirement.
- Distinguish RFC compliance issues from exploitable security vulnerabilities. Evaluate concrete threat scenarios, including risks introduced by stricter validation.
- Validate before lossy conversion: preserve parameter presence, types, and values until the relevant checks are complete.
- Treat externally supplied data as attacker-controlled until its trust has been established.
- Preserve the existing trusted-proxy model; a syntactically valid forwarded header is not necessarily trustworthy.
- The resource authorized by Heimdall must correspond to the resource ultimately processed downstream. Investigate divergent interpretations by Heimdall, integrating proxies, and upstream services.
- Reject malformed, incomplete, ambiguous, or unverifiable security-relevant input unless a different behavior is explicitly part of a secure contract. Do not turn a validation failure into a successful authorization decision.
- Distinguish absent input from explicitly supplied but invalid input. Do not conceal parsing or validation failures with a fallback to another resource, identity, or request context.
- Do not execute authorization rules against an invalid or incomplete request context. A failed validation must not depend on rule precedence or permissive default rules to remain fail-closed.
- For URL and path changes, consider raw, escaped, and decoded forms; percent encoding, encoded separators, dot segments, repeated separators, query strings, and downstream normalization.
- For rule and policy changes, consider overlapping matches, rule precedence, default rules, missing matches, and attacker-controlled attributes.
- Never relax authentication, authorization, credential, signature, or rule validation merely to satisfy tests. Assess security and compatibility implications explicitly.
- Preserve request-specific identity and authorization state across concurrency, pooling, and object reuse. Reset reusable state so information cannot leak between requests.
- Ensure cache keys include every property relevant to a security decision; do not reuse cached authorization state across incompatible identities, requests, or contexts.
- Do not expose credentials, tokens, private keys, signing material, or other secrets through logs, errors, tests, examples, or documentation.

## Test design

- Unit tests for a function or method should collectively cover its meaningful positive and negative branches. Keep individual test functions focused on coherent behaviors or scenarios. 
- Higher-level tests should exercise orchestration and error propagation, not duplicate detailed validation tests of its dependencies.
- When refactoring responsibilities, move the corresponding tests to the appropriate target functions and remove obsolete or overlapping scenarios.
- Before modifying tests, inspect their existing structure and comparable tests in the same package. Follow established setup, execution, assertion, and subtest patterns unless a different approach makes the tests simpler and easier to understand.
- Prefer extending existing test functions when new cases fit naturally without compromising readability. Use small, closely related subtests when they simplify different setup or assertions. Prefer separate test functions for substantial or structurally different scenarios. Do not force unrelated scenarios into the same test function or table.
- Use table-driven tests only when they improve clarity. Keep cases independently understandable without unnecessary helpers or abstraction (KISS before DRY). Preserve established assertion patterns, such as separating function calls from assertions and keeping case-specific assertions in existing assertion callbacks, unless doing so would increase complexity.
- Add only cases for new behavior, regressions, or genuinely uncovered edges; avoid overlapping scenarios and repeated testing of dependency behavior.
- Structure tests consistently using // GIVEN, // WHEN, and // THEN comments to separate setup, execution of the behavior under test, and assertions. Apply this convention to new and modified tests, even if existing tests do not consistently use these comments.
- Put end-to-end authorization, proxying, and cross-adapter workflows in integration tests rather than repeating entire workflows in unit tests.
- Assert observable contracts, including partial results and error identity or wrapping (`errors.Is` where appropriate), rather than incidental implementation details.
- Treat coverage as a diagnostic, not a target percentage. Inspect whether changed functions' meaningful branches have appropriate tests. Prefer removing unreachable or redundant code over adding artificial tests solely to increase coverage.
- For security-sensitive changes, cover relevant malformed, missing, duplicate, ambiguous, encoded, and adversarial inputs, alongside valid controls.
- Test security invariants at the component responsible for enforcing them, not only through higher-level layers.
- For bug fixes, add a reproducing regression case and verify that it fails before implementing the fix, where practical.
- Keep tests deterministic; prefer local fakes, fixtures, and mocks over unnecessary external dependencies.
- Regenerate mocks through the repository's configured Mockery workflow. Do not edit generated mocks manually.
- Before handoff, review modified tests against their original structure and comparable tests. Check test ownership, readability, unnecessary complexity, overlapping scenarios, and deviations from established conventions.

## Performance

- Prioritize common request and authorization paths while accounting for attacker-controlled input sizes and complexity.
- For changes to existing hot paths, compare equivalent inputs on the branch and `main`. Measure latency, allocations, and bytes allocated across repeated runs before drawing conclusions. For release-specific fixes, also compare against the unmodified release baseline when it differs materially from `main`.
- Avoid unnecessary parsing, allocations, conversions, and repeated processing on request hot paths where practical.
- Avoid pathological scaling for untrusted inputs, without weakening required parsing or validation. Do not trade simplicity for marginal or unrelated optimizations.

## Documentation and related artifacts

- Update relevant reference documentation, Go documentation, and `README.md` where applicable when public behavior changes, without unrelated rewrites.
- Follow existing AsciiDoc structure, terminology, and examples. Verify documented configuration and integration behavior against the relevant implementation and specifications; do not invent options, defaults, or response semantics.
- Keep affected schemas, OpenAPI descriptions, Helm artifacts, and examples consistent with the implementation. Do not change unrelated artifacts.
- Use the repository's existing issue and pull-request templates.
- Inspect comparable entries before drafting issues or pull requests; verify all claims.

## Security advisories

- When preparing security advisories, follow the publication and evidence-handling requirements in [SECURITY.md](./SECURITY.md).
- Do not publish an advisory unless explicitly asked.

## Validation and delivery

- Use the Go version and dependencies declared by the project and CI.
- Follow the repository's formatting and `.golangci.yaml` configuration, including configured use of `gofmt`, `gofumpt`, `goimports`, and `gci`. Do not reformat unrelated code.
- Use the `Justfile` as the canonical development command interface; run `just` to discover available tasks.
- Run focused tests for changed code, then, when the environment allows, run:

  ```sh
  just test
  just lint
  go test -count=1 ./...
  go test -race -count=1 ./...
  go vet ./...
  git diff --check
  ```

- Run `just build` when changes can affect compilation or application composition.
- Use `just test-all` for broader changes where practical.
- Run relevant Justfile tasks for changed documentation, schemas, Helm charts, Dockerfiles, or dependencies.
- For substantial documentation changes, render and inspect the result using `just run-docs`.
- Do not weaken, skip, or remove tests merely to obtain a green run. Investigate failures before classifying them as unrelated or pre-existing.
- Before handoff, review the complete diff for scope, compatibility, security implications, test ownership, unintended formatting, and generated files.
- Report any checks that could not run, including the environment used and what remains unverified. Never claim a check passed without running it.
- Summarize changes, consequential design decisions, security and compatibility considerations, checks performed, and remaining trade-offs.
- Provide incremental patches against the agreed baseline when requested.
- Do not commit unless explicitly asked.
