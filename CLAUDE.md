# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Apache Pulsar plugins (Java 21, Maven, single module) that authenticate and authorize clients using
[Biscuit](https://www.biscuitsec.org/) tokens via `biscuit-java`. Published to Maven Central as
`com.clever-cloud:biscuit-pulsar`. Version lives in `pom.xml` (`<version>`); releases are cut by
`mvn versions:set`, tagging, and creating a GitHub release (which triggers `deploy_to_central.yml`).

## Commands

```bash
mvn clean install                          # build + unit tests + integration tests (needs Docker)
mvn clean install -DskipITs                # build + unit tests only (what CI's `build` job does via `mvn -B package`)
mvn clean install -Dmaven.test.skip=true   # build only
mvn test                                   # unit tests only
mvn test -Dtest=AuthorizationProviderBiscuitTest                          # one test class
mvn test -Dtest=AuthorizationProviderBiscuitTest#testAccessOnlyToValidData # one test method
mvn verify -Dpulsar.image=apachepulsar/pulsar:4.2.4   # integration tests against a given broker image
mvn verify -Dit.test=PulsarBrokerIT#rootTokenIsSuperUser  # one integration test
```

Integration tests are the `*IT.java` classes, run by failsafe after packaging: `PulsarBrokerIT` starts a
Pulsar standalone container (Testcontainers) with the built jar and the README's lib jars copied into
`/pulsar/lib`, both providers enabled through `PULSAR_PREFIX_*` env overrides, and a revocation list at
`/etc/biscuit/revocation_list.hex.conf`. CI runs it as a matrix (production image, latest 4.0 patch,
latest release) plus an allowed-to-fail canary on the next major's milestone.

Tests are JUnit 4 (`org.junit.Test`), with AssertJ and Mockito available. There is no linter; the
compiler runs with `-Xlint:all` so watch for new warnings. The compiler is also configured with
`-verbose`, which prints every loaded class; pipe Maven output through `tail` or `grep` (e.g.
`grep -E "Tests run|FAIL|ERROR|warning:"`) rather than reading it all.

## Architecture

Two server-side providers plugged into the broker/proxy via `broker.conf`, plus a small client-side
`Authentication` implementation. All in `com.clevercloud.biscuitpulsar`.

### Authentication: `AuthenticationProviderBiscuit`

- Auth method name is `"token"`, so it is wire-compatible with Pulsar's built-in
  `AuthenticationToken` client. Clients pass the base64url biscuit as the token.
- `initialize()` reads `biscuitPublicRootKey` (hex Ed25519 key) into a **static** `rootKey` field.
  `AuthorizationProviderBiscuit` reads that same static field, so the authentication provider must be
  initialized before authorization is used (tests do this explicitly, see `authedBiscuit()` helpers).
- `authenticate()` verifies the signature against the root key, checks revocation ids, and returns the
  role string `"biscuit:<b64url token>"`. That `biscuit:` prefix is the contract between the two
  providers: authorization re-parses the token from the role.
- If `biscuitSupportJWT=true`, a biscuit parse failure falls back to Pulsar's
  `AuthenticationProviderToken` (JWT), so both token types can coexist.
- Revocation list is loaded once at startup from `/etc/biscuit/revocation_list.hex.conf` (one hex id
  per line), falling back to the classpath resource `revocation_list.hex.conf` (the test fixture in
  `src/test/resources`).
- `hexStringToByteArray` exists because commons-codec conflicts with Pulsar's dependencies; don't
  reintroduce commons-codec.

### Authorization: `AuthorizationProviderBiscuit`

Every `allow*Async` call funnels through the private `authorize(...)` method, which:

1. If the role does not start with `biscuit:`, delegates to Pulsar's `PulsarAuthorizationProvider`
   (`defaultProvider`) so non-biscuit roles keep working.
2. Otherwise builds a biscuit `Authorizer` from the token and adds, in order: `set_time()`, the
   mandatory `check if right("admin")`, the request-specific facts, rules and checks, then `allow()`,
   and runs `authorize(runLimits)`.
3. On datalog failure, optionally falls back to `isSuperUser` (itself a biscuit authorization with no
   extra facts), otherwise returns `false`.

The datalog model: the token's authority block carries `right("admin")`; attenuated blocks add
`check if topic(...), topic_operation(...)` / `check if namespace(...), namespace_operation(...)`
checks that constrain which resources/operations the token may be used for. The provider injects
facts describing the current request (`topic("tenant","ns","topic")`, `topic_operation("produce")`,
`subscription("sub")`, ...) and a `right(...)` rule that only fires for operations in the
whitelisted operation sets, then checks `right(...)` for the requested resource. So a token is
authorized iff it is admin **and** every check in its attenuation blocks is satisfied by the request
facts.

Special cases: `LOOKUP` additionally injects `PRODUCE` and `CONSUME` operation facts (a token that can
produce or consume may look up). Tenant operations and function ops are super-user only for every role.
Cluster, broker and cluster-policy operations (Pulsar 4.x hooks) are super-user only for biscuit roles
and delegate to the default provider otherwise. Permission management (grant, revoke, get, including
the 4.x batch variants) is delegated to the default provider. Source/sink
ops return `null` (unimplemented). Grant/revoke/getPermissions are delegated to the default provider.

Run limits (`biscuitRunLimitsMaxFacts`, `...MaxIterations`, `...MaxTimeMillis`) are read in
`initialize()`, which is what Pulsar calls after the no-arg constructor. An absent or blank key takes the
`DEFAULT_RUNLIMITS_*` constant (1000 facts, 100 iterations, 20 ms); the effective values are logged at
startup and `PulsarBrokerIT` asserts that line.

### Datalog string building: `formatter/` and `operation/`

- `BiscuitFormatter` is the single place that renders Pulsar names/operations into datalog fact,
  fragment, rule and check strings. Both the provider and the tests use it, so any change to the
  fact vocabulary (predicate names, argument order) goes here.
- `TopicFormatter.sanitizeTopicName` strips the `-partition-N` suffix so checks written against the
  logical topic match every partition.
- `operation/BiscuitTopicOperation`, `BiscuitNamespaceOperation` and `BiscuitPolicyOperation` are the
  **whitelists** of Pulsar operations a biscuit may grant. Commented-out entries are deliberately
  excluded (permission management, bundles, some policies). `BiscuitPolicyOperation` derives
  `<policy>_read` for every `PolicyName` but `<policy>_write` only for the whitelisted set. Policy
  operations are encoded as `<policy>_<read|write>` strings inside `namespace_operation` /
  `topic_operation` facts. When bumping the Pulsar version, check these enums against new
  `TopicOperation`/`NamespaceOperation`/`PolicyName` values.

### Client side: `AuthenticationBiscuit` / `AuthenticationDataBiscuit`

Pulsar client `Authentication` that sends the biscuit as command data and as an
`Authorization: Bearer` header. `configure(String)` accepts a raw token, `biscuit:<token>`, or
`file:<path>`.

## Dependency notes

- `biscuit-java` is `org.biscuitsec:biscuit` (the old `com.clever-cloud:biscuit-java` stops at 2.x);
  protobuf must stay on the 3.25.x line Pulsar and biscuit-java are built against. The deployed jar is
  dropped into Pulsar's `lib/` alongside `org.biscuitsec:biscuit`, `io.vavr:vavr` and
  `net.i2p.crypto:eddsa` only; Pulsar 4 ships protobuf, re2j and gson (biscuit's datalog parser needs gson at
  runtime), so do not add those. That set is the
  `copy-broker-lib` execution in `pom.xml` and the README's install script; keep the two in sync, and
  keep transitive dependencies minimal to avoid clashes with the Pulsar classpath.
- Changes that affect what operators install or configure go in `UPGRADING.md`, per version.
- `pulsar.version` drives the `pulsar-client`, `pulsar-common` and `pulsar-broker-common` artifacts.
- The provider overrides the cluster/broker authorization hooks added in Pulsar 4.0, so the built jar
  only loads on 4.x brokers (verified on 4.0.4 and 4.2.4; 3.x fails with `NoClassDefFoundError`).
