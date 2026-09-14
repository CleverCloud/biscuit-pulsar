package com.clevercloud.biscuitpulsar;

import org.apache.pulsar.client.admin.GrantTopicPermissionOptions;
import org.apache.pulsar.client.admin.PulsarAdmin;
import org.apache.pulsar.client.admin.PulsarAdminException;
import org.apache.pulsar.client.admin.RevokeTopicPermissionOptions;
import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.Message;
import org.apache.pulsar.client.api.Producer;
import org.apache.pulsar.client.api.PulsarClient;
import org.apache.pulsar.client.api.PulsarClientException;
import org.apache.pulsar.client.api.Schema;
import org.apache.pulsar.common.policies.data.AuthAction;
import org.apache.pulsar.common.policies.data.TenantInfo;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.RevocationIdentifier;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.PulsarContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.clevercloud.biscuitpulsar.formatter.BiscuitFormatter.namespaceFact;
import static com.clevercloud.biscuitpulsar.formatter.BiscuitFormatter.topicVariableFact;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Runs the built jar inside a real Pulsar standalone broker (Testcontainers) with both providers
 * enabled, and drives it through the admin and client APIs with biscuits, the way operators and
 * tenants do. The broker image comes from {@code -Dpulsar.image} (CI runs a matrix), the jars
 * dropped into the broker's {@code lib/} are exactly the ones the README lists.
 */
public class PulsarBrokerIT {
    private static final Logger log = LoggerFactory.getLogger(PulsarBrokerIT.class);

    private static final String TENANT = "tenantIT";
    private static final String NAMESPACE = TENANT + "/ns";
    private static final String OTHER_NAMESPACE = TENANT + "/other";
    private static final String TOPIC = "persistent://" + NAMESPACE + "/topic";
    private static final String OTHER_TOPIC = "persistent://" + OTHER_NAMESPACE + "/topic";

    private static final BiscuitTestSupport support = BiscuitTestSupport.randomRoot();
    private static PulsarContainer pulsar;
    private static String adminToken;
    private static String tenantToken;
    private static String revokedToken;

    @BeforeClass
    public static void startBroker() throws Exception {
        Biscuit root = support.adminBiscuit();
        Biscuit tenant = support.attenuate(root, "check if " + namespaceFact(TENANT, "ns") + " or " + topicVariableFact(TENANT, "ns"));
        Biscuit revoked = support.adminBiscuit();
        adminToken = root.serialize_b64url();
        tenantToken = tenant.serialize_b64url();
        revokedToken = revoked.serialize_b64url();
        String revocationList = revoked.revocation_identifiers().stream().map(RevocationIdentifier::toHex).collect(Collectors.joining("\n")) + "\n";

        String image = System.getProperty("pulsar.image", "apachepulsar/pulsar:4.0.4");
        log.info("Starting {} with biscuit-pulsar from {}", image, System.getProperty("biscuitPulsar.jar"));
        pulsar = new PulsarContainer(DockerImageName.parse(image).asCompatibleSubstituteFor("apachepulsar/pulsar"))
                .withEnv("PULSAR_PREFIX_authenticationEnabled", "true")
                .withEnv("PULSAR_PREFIX_authenticationProviders", AuthenticationProviderBiscuit.class.getName())
                .withEnv("PULSAR_PREFIX_authorizationEnabled", "true")
                .withEnv("PULSAR_PREFIX_authorizationProvider", AuthorizationProviderBiscuit.class.getName())
                .withEnv(brokerConf(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY), support.publicKeyHex())
                .withEnv(brokerConf(AuthenticationProviderBiscuit.CONF_BISCUIT_SUPPORT_JWT), "false")
                // the values the README recommends, distinct from the built-in 20 ms so the wiring is observable
                .withEnv(brokerConf(AuthorizationProviderBiscuit.CONF_BISCUIT_RUNLIMITS_MAX_FACTS), "1000")
                .withEnv(brokerConf(AuthorizationProviderBiscuit.CONF_BISCUIT_RUNLIMITS_MAX_ITERATIONS), "100")
                .withEnv(brokerConf(AuthorizationProviderBiscuit.CONF_BISCUIT_RUNLIMITS_MAX_TIME), "30")
                // the broker's own client (system topics, standalone bootstrap) authenticates with the root token
                .withEnv("PULSAR_PREFIX_brokerClientAuthenticationPlugin", "org.apache.pulsar.client.impl.auth.AuthenticationToken")
                .withEnv("PULSAR_PREFIX_brokerClientAuthenticationParameters", "token:" + adminToken)
                .withCopyToContainer(Transferable.of(revocationList.getBytes(StandardCharsets.UTF_8)), "/etc/biscuit/revocation_list.hex.conf")
                .withLogConsumer(new Slf4jLogConsumer(log).withPrefix("pulsar"))
                // Testcontainers' default readiness probe is an unauthenticated GET on the admin API, which
                // Pulsar's authentication filter answers with 401 once authentication is on
                .waitingFor(Wait.forHttp("/admin/v2/clusters").forPort(PulsarContainer.BROKER_HTTP_PORT)
                        .withHeader("Authorization", "Bearer " + adminToken)
                        .forResponsePredicate("[\"standalone\"]"::equals)
                        .withStartupTimeout(Duration.ofMinutes(3)));
        for (Path jar : brokerLibJars()) {
            pulsar.withCopyFileToContainer(MountableFile.forHostPath(jar), "/pulsar/lib/" + jar.getFileName());
        }
        pulsar.start();

        try (PulsarAdmin admin = admin(adminToken)) {
            admin.tenants().createTenant(TENANT, TenantInfo.builder().allowedClusters(Set.of("standalone")).build());
            admin.namespaces().createNamespace(NAMESPACE);
            admin.namespaces().createNamespace(OTHER_NAMESPACE);
            admin.topics().createNonPartitionedTopic(TOPIC);
            admin.topics().createNonPartitionedTopic(OTHER_TOPIC);
        }
    }

    /** The env var Pulsar's apply-config-from-env.py turns into {@code key=value} in standalone.conf. */
    private static String brokerConf(String key) {
        return "PULSAR_PREFIX_" + key;
    }

    /** The plugin jar plus the dependencies Pulsar 4 does not ship (see the README's install script). */
    private static List<Path> brokerLibJars() throws Exception {
        Path jar = Path.of(System.getProperty("biscuitPulsar.jar"));
        try (Stream<Path> libs = Files.list(Path.of(System.getProperty("biscuitPulsar.lib")))) {
            return Stream.concat(Stream.of(jar), libs.filter(p -> p.toString().endsWith(".jar"))).collect(Collectors.toList());
        }
    }

    @AfterClass
    public static void stopBroker() {
        if (pulsar != null) {
            pulsar.stop();
        }
    }

    private static PulsarAdmin admin(String token) throws PulsarClientException {
        return PulsarAdmin.builder().serviceHttpUrl(pulsar.getHttpServiceUrl()).authentication(new AuthenticationBiscuit(token)).build();
    }

    private static PulsarClient client(String token) throws PulsarClientException {
        return PulsarClient.builder().serviceUrl(pulsar.getPulsarBrokerUrl()).authentication(new AuthenticationBiscuit(token)).build();
    }

    @Test
    public void runLimitsFromBrokerConfAreApplied() {
        assertTrue(pulsar.getLogs(), pulsar.getLogs().contains("Biscuit authorization run limits: maxFacts=1000, maxIterations=100, maxTime=PT0.03S"));
    }

    @Test
    public void rootTokenIsSuperUser() throws Exception {
        try (PulsarAdmin admin = admin(adminToken)) {
            assertEquals(List.of("standalone"), admin.clusters().getClusters());
            admin.clusters().getCluster("standalone");
            admin.brokers().getActiveBrokers("standalone");
            admin.namespaces().setOffloadThreshold(NAMESPACE, 1024);
            assertEquals(1024, admin.namespaces().getOffloadThreshold(NAMESPACE));
        }
    }

    /** Authorization is carried by biscuits: Pulsar's own permission store is never written, even by the root token. */
    @Test
    public void permissionManagementIsRefusedEvenForTheRootToken() throws Exception {
        try (PulsarAdmin admin = admin(adminToken)) {
            List<ThrowingRunnable> writes = List.of(
                    () -> admin.namespaces().grantPermissionOnNamespace(NAMESPACE, "someone", Set.of(AuthAction.produce)),
                    () -> admin.topics().grantPermission(TOPIC, "someone", Set.of(AuthAction.produce)),
                    () -> admin.namespaces().grantPermissionOnTopics(List.of(GrantTopicPermissionOptions.builder().topic(TOPIC).role("someone").actions(Set.of(AuthAction.produce)).build())),
                    () -> admin.namespaces().grantPermissionOnSubscription(NAMESPACE, "it", Set.of("someone")),
                    () -> admin.namespaces().revokePermissionsOnNamespace(NAMESPACE, "someone"),
                    () -> admin.topics().revokePermissions(TOPIC, "someone"),
                    () -> admin.namespaces().revokePermissionOnTopics(List.of(RevokeTopicPermissionOptions.builder().topic(TOPIC).role("someone").build())),
                    () -> admin.namespaces().revokePermissionOnSubscription(NAMESPACE, "it", "someone"));
            for (ThrowingRunnable write : writes) {
                PulsarAdminException.NotAllowedException refused = assertThrows(PulsarAdminException.NotAllowedException.class, write);
                assertTrue(refused.getMessage(), refused.getMessage().contains("permission management is disabled"));
            }

            assertTrue(admin.namespaces().getPermissions(NAMESPACE).isEmpty());
            assertTrue(admin.topics().getPermissions(TOPIC).isEmpty());
            assertTrue(admin.namespaces().getPermissionOnSubscription(NAMESPACE).isEmpty());

            // deleting a partitioned topic no longer involves the permission store
            String partitioned = TOPIC + "-partitioned";
            admin.topics().createPartitionedTopic(partitioned, 2);
            admin.topics().deletePartitionedTopic(partitioned);
        }
    }

    @Test
    public void tenantTokenIsScopedToItsNamespace() throws Exception {
        try (PulsarAdmin tenant = admin(tenantToken)) {
            tenant.topics().createNonPartitionedTopic(TOPIC + "-created-by-tenant");
            // offload policy: readable by the tenant, writable by the super-user only (see README, and axo's
            // storage-policies endpoint which writes thresholds with the cluster root token)
            tenant.namespaces().getOffloadThreshold(NAMESPACE);

            assertThrows(PulsarAdminException.NotAuthorizedException.class, () -> tenant.topics().createNonPartitionedTopic(OTHER_TOPIC + "-created-by-tenant"));
            assertThrows(PulsarAdminException.NotAuthorizedException.class, () -> tenant.namespaces().setOffloadThreshold(NAMESPACE, 2048));
            assertThrows(PulsarAdminException.NotAuthorizedException.class, () -> tenant.clusters().getCluster("standalone"));
            assertThrows(PulsarAdminException.NotAuthorizedException.class, () -> tenant.brokers().getActiveBrokers("standalone"));
            assertThrows(PulsarAdminException.NotAuthorizedException.class, () -> tenant.tenants().getTenants());
        }
    }

    @Test
    public void tenantTokenProducesAndConsumesInItsNamespaceOnly() throws Exception {
        try (PulsarClient client = client(tenantToken)) {
            try (Consumer<String> consumer = client.newConsumer(Schema.STRING).topic(TOPIC).subscriptionName("it").subscribe();
                 Producer<String> producer = client.newProducer(Schema.STRING).topic(TOPIC).create()) {
                producer.send("hello");
                Message<String> message = consumer.receive(30, TimeUnit.SECONDS);
                assertEquals("hello", message.getValue());
                consumer.acknowledge(message);
            }
            assertThrows(PulsarClientException.AuthorizationException.class, () -> client.newProducer(Schema.STRING).topic(OTHER_TOPIC).create());
            assertThrows(PulsarClientException.AuthorizationException.class, () -> client.newConsumer(Schema.STRING).topic(OTHER_TOPIC).subscriptionName("it").subscribe());
        }
    }

    @Test
    public void revokedTokenIsRejectedAtAuthentication() throws Exception {
        try (PulsarAdmin revoked = admin(revokedToken)) {
            assertThrows(PulsarAdminException.NotAuthorizedException.class, () -> revoked.clusters().getCluster("standalone"));
        }
        try (PulsarClient client = client(revokedToken)) {
            assertThrows(PulsarClientException.AuthenticationException.class, () -> client.newProducer(Schema.STRING).topic(TOPIC).create());
        }
    }
}
