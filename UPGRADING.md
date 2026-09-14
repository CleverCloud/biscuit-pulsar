# Upgrading

## From 3.7.x to 4.0.0

4.0.0 changes what must be installed on the Pulsar nodes, and requires Pulsar 4.x. Tokens, rights and
configuration keys are unchanged, so nodes can be upgraded one at a time.

Everything below applies to every node where the plugin is installed: brokers, and proxies if their
`proxy.conf` uses it.

### Before you start

1. **Run Pulsar 4.x.** 4.0.0 does not load on Pulsar 3.x brokers (`NoClassDefFoundError` at startup).
   If your nodes are still on 3.x, upgrade Pulsar first and keep plugin 3.7.1: the 3.7.1 jars load and
   authorize correctly on Pulsar 4.
2. **Check the revocation list file.** `/etc/biscuit/revocation_list.hex.conf` must exist on every node,
   even empty. Without it the node fails to start with a `NullPointerException` in `loadRevocationList`.
   This was already true in 3.7.1.
3. **Review the run limits.** 4.0.0 is the first version that reads these settings. Earlier versions
   ignored them and always used 1000 facts, 100 iterations and 20 ms.

   ```bash
   biscuitRunLimitsMaxFacts=1000
   biscuitRunLimitsMaxIterations=100
   biscuitRunLimitsMaxTimeMillis=30
   ```

   A key that is absent or blank keeps its old default. A value you set, such as the 30 ms from the
   README's example, now takes effect. If authorization times out, it is denied.

### Upgrade a node

1. Stop the node.
2. In `pulsar/lib`, remove the jars installed for 3.7.x:
   - `biscuit-pulsar-3.7.1.jar`
   - the biscuit-java jar: `biscuit-3.0.1.jar`, or `biscuit-java-*.jar` if it came from the old README script
   - `vavr-0.10.3.jar`
   - `protobuf-java-3.25.0.jar`. Pulsar 4 ships its own protobuf. Keep Pulsar's jar, whose name starts
     with `com.google.protobuf-`.

   `eddsa-0.3.0.jar` is unchanged and can stay.
3. Install the 4.0.0 jars:

   ```bash
   wget -P "pulsar/lib" "https://repo1.maven.org/maven2/io/vavr/vavr/0.10.7/vavr-0.10.7.jar"
   wget -P "pulsar/lib" "https://repo1.maven.org/maven2/org/biscuitsec/biscuit/4.0.1/biscuit-4.0.1.jar"
   wget -P "pulsar/lib" "https://repo1.maven.org/maven2/com/clever-cloud/biscuit-pulsar/4.0.0/biscuit-pulsar-4.0.0.jar"
   ```

4. Start the node and check its log for these lines:

   ```text
   com.clevercloud.biscuitpulsar.AuthorizationProviderBiscuit - Biscuit authorization run limits: maxFacts=1000, maxIterations=100, maxTime=PT0.03S
   org.apache.pulsar.broker.authorization.AuthorizationService - com.clevercloud.biscuitpulsar.AuthorizationProviderBiscuit has been loaded.
   com.clevercloud.biscuitpulsar.AuthenticationProviderBiscuit - Loaded revocation list with 0 item(s).
   ```

   The run limits line is new in 4.0.0, so it confirms the new jar is loaded and shows the limits in effect.
5. Call the admin API with the cluster root token before moving to the next node:

   ```bash
   curl -H "Authorization: Bearer $ROOT_BISCUIT" http://<node>:8080/admin/v2/clusters
   ```

### What changes for users

- **Tenant tokens**: no change. The rights vocabulary and the operation whitelists are the same as in 3.7.1.
- **Batch grant and revoke on topics** (`POST /admin/v2/namespaces/grantPermissionsOnTopics` and
  `revokePermissionsOnTopics`) now work. With 3.7.1 on Pulsar 4 they answered `409`.
- **Cluster, broker and tenant operations** remain super-user only.

### Roll back

Stop the node, put the 3.7.1 jars back, including `protobuf-java-3.25.0.jar` if you had it, and restart.
There is no data or metadata migration. Permissions granted after the upgrade stay in Pulsar's metadata.

### Applications using the client class

`AuthenticationBiscuit` is unchanged. The artifact now depends on `org.biscuitsec:biscuit` 4.0.1 and
`pulsar-client` 4.2.4, so align your own Pulsar client version or exclude it. Java 21 is required, as
since 3.7.0.
