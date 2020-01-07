# Pulsar Biscuit Authentication & Authorization plugins

## Tests

```bash
# run all tests
mvn clean install

# build without tests
mvn clean install -Dmaven.test.skip=true

# run AuthorizationProviderBiscuitTest in module biscuit-pulsar
mvn clean install -Dtest=AuthorizationProviderBiscuitTest -pl biscuit-pulsar
```

## Configuration

copy jars (from `build/libs`) to pulsar's `/lib` directory:
- biscuit-pulsar
- vavr
- vavr-match
- protobuf
- commons-codec
- biscuit-java
- curve25519-elisabeth

```bash
# Enable authentication
authenticationEnabled=true

# Autentication provider name list, which is comma separated list of class names
authenticationProviders=com.clevercloud.biscuitpulsar.AuthenticationProviderBiscuit

# Enforce authorization
authorizationEnabled=true

# Authorization provider fully qualified class-name
authorizationProvider=com.clevercloud.biscuitpulsar.AuthorizationProviderBiscuit

# Biscuit root signing key
biscuitPublicRootKey=<BiscuitPublicRootKeyHexa>

superUserRoles=admin
```

## Versions

Change version:

```bash
mvn versions:set -DnewVersion=x.y.z-SNAPSHOT
mvn versions:commit
```
