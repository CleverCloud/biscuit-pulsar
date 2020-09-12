# Pulsar Biscuit Authentication & Authorization plugins

[![Bintray Version](https://img.shields.io/bintray/v/clevercloud/maven/biscuit-pulsar.svg)](https://bintray.com/clevercloud/maven/biscuit-pulsar#)
[![Central Version](https://img.shields.io/maven-central/v/com.clever-cloud/biscuit-pulsar)](https://mvnrepository.com/artifact/com.clever-cloud/biscuit-pulsar)
[![Nexus Version](https://img.shields.io/nexus/r/com.clever-cloud/biscuit-pulsar?server=https%3A%2F%2Foss.sonatype.org)](https://search.maven.org/artifact/com.clever-cloud/biscuit-pulsar)

## Status

We are using 1.5.5-SNAPSHOT at Clever Cloud.

## Build & Tests

```bash
# run all tests and build
mvn clean install

# build module like biscuit-pulsar only
mvn clean install -pl biscuit-pulsar

# build without tests
mvn clean install -Dmaven.test.skip=true

# run AuthorizationProviderBiscuitTest in module biscuit-pulsar
mvn clean install -Dtest=AuthorizationProviderBiscuitTest -pl biscuit-pulsar
```

## Informations

`biscuit-pulsar` needs protobuf 3.8.0+ as defined in its `pom.xml`.

## Configuration

The listed dependencies can be necessary to add to the /lib of pulsar folder as jars:

- biscuit-pulsar
- vavr
- vavr-match
- protobuf
- commons-codec
- biscuit-java
- curve25519-elisabeth

We currently are using this script to put libs on pulsar nodes:

```bash
#!/bin/bash

wget -P "pulsar/lib" "https://repo1.maven.org/maven2/cafe/cryptography/curve25519-elisabeth/0.1.0/curve25519-elisabeth-0.1.0.jar"
wget -P "pulsar/lib" "https://repo1.maven.org/maven2/io/vavr/vavr/0.10.2/vavr-0.10.2.jar"
wget -P "pulsar/lib" "https://repo1.maven.org/maven2/com/clever-cloud/biscuit-java/0.4.0/biscuit-java-0.4.0.jar"
wget -P "pulsar/lib" "https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/3.8.0/protobuf-java-3.8.0.jar"
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
    .authentication(new AuthenticationToken(<BISCUIT_b64 or JWT>))
    .serviceUrl("pulsar://localhost:6650")
    .build();
```

## Publish

You need to define this in `~/.m2/settings.xml` using your bintray APIKEY on the Clever Cloud organisation:

```xml
<server>
  <id>bintray-repo-maven-biscuit-pulsar</id>
  <username>@@BINTRAY_USERNAME@</username>
  <password>@@YOUR_BINTRAY_API_KEY@@</password>
</server>
```

Then run

```bash
mvn deploy
```

It will prompt for GPG passphrase stored on Clever Cloud vault (search for `maven@clever-cloud.com`).

Then on bintray package homepage run Sync to Central to push to Maven Central.
