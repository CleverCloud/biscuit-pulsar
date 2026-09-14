# Pulsar Biscuit Authentication & Authorization plugins

[![Tests](https://github.com/clevercloud/biscuit-pulsar/actions/workflows/java_ci.yml/badge.svg)](https://github.com/CleverCloud/biscuit-pulsar/actions/workflows/java_ci.yml)

[![Central Version](https://img.shields.io/maven-central/v/com.clever-cloud/biscuit-pulsar)](https://mvnrepository.com/artifact/com.clever-cloud/biscuit-pulsar)
[![Nexus Version](https://img.shields.io/nexus/r/com.clever-cloud/biscuit-pulsar?server=https%3A%2F%2Fs01.oss.sonatype.org)](https://search.maven.org/artifact/com.clever-cloud/biscuit-pulsar)

## Requirements

`biscuit-pulsar` needs `protobuf` 3.25.x (the version pinned by both Pulsar and biscuit-java).

Since 3.8.0 the plugins require Pulsar **4.x** brokers (they implement the cluster/broker
authorization hooks Pulsar 4.0 introduced, so the classes no longer load on 3.x).

## Configuration

The listed dependencies must be added to the `/lib` of the pulsar folder as jars (Pulsar 4 already ships
`protobuf` and `re2j`; the integration tests install these same artifacts, at the versions of `pom.xml`):

- `net.i2p.crypto:eddsa`
- `io.vavr:vavr`
- `org.biscuitsec:biscuit` (biscuit-java)
- `com.clever-cloud:biscuit-pulsar`

We currently are using this script to put libs on pulsar nodes:

```bash
#!/bin/bash

wget -P "pulsar/lib" "https://repo1.maven.org/maven2/net/i2p/crypto/eddsa/0.3.0/eddsa-0.3.0.jar"
wget -P "pulsar/lib" "https://repo1.maven.org/maven2/io/vavr/vavr/0.10.7/vavr-0.10.7.jar"
wget -P "pulsar/lib" "https://repo1.maven.org/maven2/org/biscuitsec/biscuit/4.0.1/biscuit-4.0.1.jar"
wget -P "pulsar/lib" "https://repo1.maven.org/maven2/com/clever-cloud/biscuit-pulsar/<VERSION>/biscuit-pulsar-<VERSION>.jar"
```

For nodes configuration:

In your `broker.conf` | `proxy.conf` | `standalone.conf`:

```bash
# Enable authentication
authenticationEnabled=true

# Autentication provider name list, which is comma separated list of class names
authenticationProviders=com.clevercloud.biscuitpulsar.AuthenticationProviderBiscuit

# Enforce authorization
authorizationEnabled=true

# Authorization provider fully qualified class-name
authorizationProvider=com.clevercloud.biscuitpulsar.AuthorizationProviderBiscuit

### --- Biscuit Authentication Provider --- ###
biscuitPublicRootKey=@@BISCUIT_PUBLIC_ROOT_KEY@@
# support JWT side by side with Biscuit for AuthenticationToken
biscuitSupportJWT=true|false
# biscuit verify run limits before TimeOut
biscuitRunLimitsMaxFacts=1000
biscuitRunLimitsMaxIterations=100
biscuitRunLimitsMaxTimeMillis=30
```

```bash
#!/bin/bash

sed -i -e "s/@@BISCUIT_PUBLIC_ROOT_KEY@@/$1/" broker.conf
sed -i -e "s/@@BISCUIT_PUBLIC_ROOT_KEY@@/$1/" proxy.conf
sed -i -e "s/@@BISCUIT_PUBLIC_ROOT_KEY@@/$1/" standalone.conf
```

## Revocation list

Revoked biscuit must have their revocation ids contained in `/etc/biscuit/revocation_list.hex.conf`, one revocation per line in hexadecimals. [Here is an example](https://raw.githubusercontent.com/CleverCloud/biscuit-pulsar/master/src/test/resources/revocation_list.hex.conf).

## Usage

```java
PulsarClient client = PulsarClient.builder()
    .authentication(new AuthenticationToken("<BISCUIT_b64 or JWT>"))
    .serviceUrl("pulsar://localhost:6650")
    .build();
```

## Development

```bash
# unit tests + integration tests (a real Pulsar broker via Testcontainers, needs Docker) + build
mvn clean install

# integration tests against another broker image (CI runs 4.0.4, 4.0.13, 4.2.4 and a 5.x canary)
mvn clean install -Dpulsar.image=apachepulsar/pulsar:4.2.4

# unit tests only
mvn clean install -DskipITs

# build without tests
mvn clean install -Dmaven.test.skip=true
```

## Publish

### Release process

```bash
mvn versions:set -DnewVersion=<NEW-VERSION>
```

Commit and tag the version. Then push and create a **GitHub release**.

Finally, publishing to Nexus and Maven Central is **automatically triggered by creating a GitHub release** using GitHub Actions.

```bash
mvn versions:set -DnewVersion=<NEW-VERSION With Minor +1 and -SNAPSHOT>
```

Commit and push.

### GitHub Actions Requirements

Publish requires following secrets:

* `OSSRH_USERNAME` the Sonatype username
* `OSSRH_TOKEN` the Sonatype token
* `OSSRH_GPG_SECRET_KEY` the gpg private key used to sign packages
* `OSSRH_GPG_SECRET_KEY_PASSWORD` the gpg private key password

These are stored in GitHub organisation's secrets.
