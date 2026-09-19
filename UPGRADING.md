# Upgrading

## From 4.0.0 to 4.0.1

4.0.1 stops managing Pulsar's own permissions, because authorization is carried by the biscuit tokens. Every
grant and revoke call is refused with `405 Method Not Allowed`, even for the cluster root token: namespace,
topic and subscription permissions, and the batch calls on topics. Permission reads still answer, and deleting
a topic no longer touches Pulsar's permission store. Biscuit tokens, rights and configuration are unchanged.

### Before you upgrade

Check that no Pulsar permission is stored. Biscuit tokens ignore these permissions, but a stored grant still
authorizes a non-biscuit role, such as a JWT when `biscuitSupportJWT` is on, and 4.0.1 cannot revoke it.

```bash
pulsar-admin namespaces permissions <tenant>/<namespace>
pulsar-admin namespaces subscription-permission <tenant>/<namespace>
pulsar-admin topics permissions persistent://<tenant>/<namespace>/<topic>
```

If one of them lists a role, revoke it while the node still runs 4.0.0:

```bash
pulsar-admin namespaces revoke-permission <tenant>/<namespace> --role <role>
pulsar-admin namespaces revoke-subscription-permission <tenant>/<namespace> --subscription <subscription> --role <role>
pulsar-admin topics revoke-permission persistent://<tenant>/<namespace>/<topic> --role <role>
```

### Upgrade a node

Stop the node, replace `biscuit-pulsar-4.0.0.jar` with `biscuit-pulsar-4.0.1.jar` in `pulsar/lib`, and start it.
The other jars and the configuration stay as they are.

```bash
wget -P "pulsar/lib" "https://repo1.maven.org/maven2/com/clever-cloud/biscuit-pulsar/4.0.1/biscuit-pulsar-4.0.1.jar"
```

## From 3.6.x to 4.0.x

Follow [From 3.7.x to 4.0.x](#from-37x-to-40x) below, with these differences, which came with 3.7.0:

- **Java 21 at runtime.** 3.6.x is built for Java 17; 3.7.0 and later are class file 65. On an older JRE
  the node crash-loops on `UnsupportedClassVersionError`, so move the node to Java 21 first. 3.6.x runs on
  Java 21 too, so that step can be done on its own.
- **Token signatures are checked when a client connects.** 3.6.x only parsed the token at authentication
  and verified its signature later, at authorization, so a token with a bad signature could connect and was
  refused on its first authorized operation. It is now refused at connection. Valid tokens are not affected.
- **Consumers restricted to a subscription work.** A token whose checks name a subscription was refused by
  3.6.x; it now authorizes that subscription. Tokens without a subscription check behave as before.
- **Permission reads answer.** 3.6.x had none, so Pulsar Manager's permission views failed.
- **Different protobuf jar.** 3.6.x installed `protobuf-java-3.16.3.jar`, not `protobuf-java-3.25.0.jar`. It
  must be removed too, or it stays in `pulsar/lib` next to Pulsar 4's own protobuf.
- The other jars to remove are the same, with `biscuit-pulsar-3.6.1.jar` in place of `biscuit-pulsar-3.7.1.jar`.

## From 3.7.x to 4.0.x

4.0.x changes what must be installed on the Pulsar nodes, and requires Pulsar 4.x. Tokens, rights and
configuration keys are unchanged, so nodes can be upgraded one at a time. Go straight to 4.0.1, unless a
Pulsar permission is stored (step 4 below).

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
4. **Check for stored Pulsar permissions**, with the commands of [From 4.0.0 to 4.0.1](#before-you-upgrade).
   3.7.1 accepted grants but could not revoke namespace or topic grants, and 4.0.1 refuses both. If one is stored, upgrade to 4.0.0
   first, revoke it there, then move to 4.0.1.

### Upgrade a node

1. Stop the node.
2. In `pulsar/lib`, remove the jars installed for 3.7.x or 3.6.x:
   - `biscuit-pulsar-3.7.1.jar` (or `biscuit-pulsar-3.6.1.jar`)
   - the biscuit-java jar: `biscuit-3.0.1.jar`, or `biscuit-java-*.jar` if it came from the old README script
   - `vavr-0.10.3.jar`
   - `protobuf-java-3.25.0.jar` (`protobuf-java-3.16.3.jar` from 3.6.x). Pulsar 4 ships its own protobuf.
     Keep Pulsar's jar, whose name starts with `com.google.protobuf-`.

   `eddsa-0.3.0.jar` is unchanged and can stay.
3. Install the 4.0.0 jars:

   ```bash
   wget -P "pulsar/lib" "https://repo1.maven.org/maven2/io/vavr/vavr/0.10.7/vavr-0.10.7.jar"
   wget -P "pulsar/lib" "https://repo1.maven.org/maven2/org/biscuitsec/biscuit/4.0.1/biscuit-4.0.1.jar"
   wget -P "pulsar/lib" "https://repo1.maven.org/maven2/com/clever-cloud/biscuit-pulsar/4.0.1/biscuit-pulsar-4.0.1.jar"
   ```

4. Start the node and check its log for these lines:

   ```text
   com.clevercloud.biscuitpulsar.AuthorizationProviderBiscuit - Biscuit authorization run limits: maxFacts=1000, maxIterations=100, maxTime=PT0.03S
   org.apache.pulsar.broker.authorization.AuthorizationService - com.clevercloud.biscuitpulsar.AuthorizationProviderBiscuit has been loaded.
   com.clevercloud.biscuitpulsar.AuthenticationProviderBiscuit - Loaded revocation list with 0 item(s).
   ```

   The run limits line is new in 4.0.x, so it confirms the new jar is loaded and shows the limits in effect.
5. Call the admin API with the cluster root token before moving to the next node:

   ```bash
   curl -H "Authorization: Bearer $ROOT_BISCUIT" http://<node>:8080/admin/v2/clusters
   ```

### What changes for users

- **Tenant tokens**: no change. The rights vocabulary and the operation whitelists are the same as in 3.7.1.
- **Pulsar permission management** (grant and revoke on namespaces, topics and subscriptions, and the batch
  calls on topics) answers `405` from 4.0.1. Authorization is carried by the biscuit tokens.
- **Cluster, broker and tenant operations** remain super-user only.

### Roll back

Stop the node, put the 3.7.1 jars back, including `protobuf-java-3.25.0.jar` if you had it, and restart.
From 3.6.x, put back `biscuit-pulsar-3.6.1.jar` and `protobuf-java-3.16.3.jar` instead.
There is no data or metadata migration.

### Applications using the client class

`AuthenticationBiscuit` is unchanged. The artifact now depends on `org.biscuitsec:biscuit` 4.0.1 and
`pulsar-client` 4.2.4, so align your own Pulsar client version or exclude it. Java 21 is required, as
since 3.7.0.
