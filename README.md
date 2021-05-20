# Pulsar Biscuit Authentication & Authorization plugins

[![Central Version](https://img.shields.io/maven-central/v/com.clever-cloud/biscuit-pulsar)](https://mvnrepository.com/artifact/com.clever-cloud/biscuit-pulsar)
[![Nexus Version](https://img.shields.io/nexus/r/com.clever-cloud/biscuit-pulsar?server=https%3A%2F%2Foss.sonatype.org)](https://search.maven.org/artifact/com.clever-cloud/biscuit-pulsar)

## Requirements

`biscuit-pulsar` needs protobuf 3.13.

## Configuration

The listed dependencies can be necessary to add to the /lib of pulsar folder as jars:

- curve25519-elisabeth
- vavr
- protobuf
- biscuit-java
- biscuit-pulsar

We currently are using this script to put libs on pulsar nodes:

```bash
#!/bin/bash

wget -P "pulsar/lib" "https://repo1.maven.org/maven2/cafe/cryptography/curve25519-elisabeth/0.1.0/curve25519-elisabeth-0.1.0.jar"
wget -P "pulsar/lib" "https://repo1.maven.org/maven2/io/vavr/vavr/0.10.3/vavr-0.10.3.jar"
wget -P "pulsar/lib" "https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/3.13.0/protobuf-java-3.13.0.jar"
wget -P "pulsar/lib" "https://repo1.maven.org/maven2/com/clever-cloud/biscuit-java/<VERSION>/biscuit-java-<VERSION>.jar"
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
biscuitSealingKey=@@BISCUIT_PUBLIC_SEALING_KEY@@
# support JWT side by side with Biscuit for AuthenticationToken
biscuitSupportJWT=true|false
```

```bash
#!/bin/bash

sed -i -e "s/@@BISCUIT_PUBLIC_ROOT_KEY@@/$1/" broker.conf
sed -i -e "s/@@BISCUIT_PUBLIC_ROOT_KEY@@/$1/" proxy.conf
sed -i -e "s/@@BISCUIT_PUBLIC_ROOT_KEY@@/$1/" standalone.conf

sed -i -e "s/@@BISCUIT_PUBLIC_SEALING_KEY@@/$2/" broker.conf
sed -i -e "s/@@BISCUIT_PUBLIC_SEALING_KEY@@/$2/" proxy.conf
sed -i -e "s/@@BISCUIT_PUBLIC_SEALING_KEY@@/$2/" standalone.conf
```

## Usage

```java
PulsarClient client = PulsarClient.builder()
    .authentication(new AuthenticationToken("<BISCUIT_b64 or JWT>"))
    .serviceUrl("pulsar://localhost:6650")
    .build();
```

## Development

```bash
# run all tests and build
mvn clean install

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
