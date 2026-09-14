package com.clevercloud.biscuitpulsar;

import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authorization.PulsarAuthorizationProvider;
import org.apache.pulsar.broker.resources.PulsarResources;
import org.apache.pulsar.client.admin.GrantTopicPermissionOptions;
import org.apache.pulsar.client.admin.RevokeTopicPermissionOptions;
import org.apache.pulsar.common.naming.NamespaceName;
import org.apache.pulsar.common.naming.TopicName;
import org.apache.pulsar.common.policies.data.AuthAction;
import org.apache.pulsar.common.policies.data.BrokerOperation;
import org.apache.pulsar.common.policies.data.ClusterOperation;
import org.apache.pulsar.common.policies.data.NamespaceOperation;
import org.apache.pulsar.common.policies.data.PolicyName;
import org.apache.pulsar.common.policies.data.PolicyOperation;
import org.apache.pulsar.common.policies.data.TopicOperation;
import org.biscuitsec.biscuit.token.Biscuit;
import org.junit.Test;

import java.lang.reflect.Field;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static com.clevercloud.biscuitpulsar.BiscuitTestSupport.*;
import static com.clevercloud.biscuitpulsar.formatter.BiscuitFormatter.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.junit.Assert.assertTrue;

public class AuthorizationProviderBiscuitTest {
    private final BiscuitTestSupport support = BiscuitTestSupport.randomRoot();
    private final AuthorizationProviderBiscuit provider = new AuthorizationProviderBiscuit();

    /** The usual tenant scope: one namespace and every topic in it. */
    private String namespaceScope() {
        return "check if " + namespaceFact(TENANT, NAMESPACE) + " or " + topicVariableFact(TENANT, NAMESPACE);
    }

    private boolean topicOp(String role, String topic, TopicOperation operation) throws Exception {
        return topicOp(role, topic, operation, null);
    }

    private boolean topicOp(String role, String topic, TopicOperation operation, AuthenticationDataSource authData) throws Exception {
        return provider.allowTopicOperationAsync(TopicName.get(topic), role, operation, authData).get();
    }

    private boolean namespaceOp(String role, String namespace, NamespaceOperation operation) throws Exception {
        return provider.allowNamespaceOperationAsync(NamespaceName.get(namespace), role, operation, null).get();
    }

    private boolean namespacePolicy(String role, String namespace, PolicyName policy, PolicyOperation operation) throws Exception {
        return provider.allowNamespacePolicyOperationAsync(NamespaceName.get(namespace), policy, operation, role, null).get();
    }

    private boolean topicPolicy(String role, String topic, PolicyName policy, PolicyOperation operation) throws Exception {
        return provider.allowTopicPolicyOperationAsync(TopicName.get(topic), role, policy, operation, null).get();
    }

    @Test
    public void testAccessOnlyToValidData() throws Exception {
        String role = support.authed(support.adminBiscuit(topicOperationCheck(TopicName.get(TOPIC_PATH), TopicOperation.PRODUCE)));

        assertTrue(topicOp(role, TOPIC_PATH, TopicOperation.PRODUCE));
        assertFalse(topicOp(role, TENANT + "/namespaceForbidden/" + TOPIC, TopicOperation.PRODUCE));
        assertFalse(topicOp(role, "tenantForbidden/" + NAMESPACE + "/" + TOPIC, TopicOperation.PRODUCE));
        assertFalse(topicOp(role, NS + "/topicForbidden", TopicOperation.PRODUCE));
    }

    @Test
    public void testProduceAndNotConsumeOnTopic() throws Exception {
        String role = support.authed(support.adminBiscuit(topicOperationCheck(TopicName.get(TOPIC_PATH), TopicOperation.PRODUCE)));

        assertTrue(topicOp(role, TOPIC_PATH, TopicOperation.PRODUCE));
        assertFalse(topicOp(role, TOPIC_PATH, TopicOperation.CONSUME));
    }

    @Test
    public void testProduceAndConsumeOnDifferentNamespacesTopics() throws Exception {
        String ns1Topic = TENANT + "/ns1/" + TOPIC;
        String ns2Topic = TENANT + "/ns2/" + TOPIC;
        String ns1Consume = topicOperation(TopicName.get(ns1Topic), TopicOperation.CONSUME);
        String ns2Produce = topicOperation(TopicName.get(ns2Topic), TopicOperation.PRODUCE);
        String role = support.authed(support.adminBiscuit(String.format("check if %s or %s", ns1Consume, ns2Produce)));

        assertTrue(topicOp(role, ns1Topic, TopicOperation.CONSUME));
        assertTrue(topicOp(role, ns2Topic, TopicOperation.PRODUCE));
        assertFalse(topicOp(role, ns1Topic, TopicOperation.PRODUCE));
        assertFalse(topicOp(role, ns2Topic, TopicOperation.CONSUME));
    }

    @Test
    public void testProduceAndNotConsumeAttenuatedOnTopic() throws Exception {
        Biscuit rootBiscuit = support.adminBiscuit();
        String admin = support.authed(rootBiscuit);
        assertTrue(topicOp(admin, TOPIC_PATH, TopicOperation.PRODUCE));
        assertTrue(topicOp(admin, TOPIC_PATH, TopicOperation.CONSUME));

        String role = support.authed(support.attenuate(rootBiscuit, topicOperationCheck(TopicName.get(TOPIC_PATH), TopicOperation.PRODUCE)));
        assertTrue(topicOp(role, TOPIC_PATH, TopicOperation.PRODUCE));
        assertFalse(topicOp(role, TOPIC_PATH, TopicOperation.CONSUME));
    }

    @Test
    public void testConsumeAndNotProduceOnTopic() throws Exception {
        String role = support.authed(support.adminBiscuit(topicOperationCheck(TopicName.get(TOPIC_PATH), TopicOperation.CONSUME)));

        assertFalse(topicOp(role, TOPIC_PATH, TopicOperation.PRODUCE));
        assertTrue(topicOp(role, TOPIC_PATH, TopicOperation.CONSUME));
    }

    @Test
    public void testConsumerAndNotProduceAttenuatedOnTopic() throws Exception {
        Biscuit rootBiscuit = support.adminBiscuit();
        String admin = support.authed(rootBiscuit);
        assertTrue(topicOp(admin, TOPIC_PATH, TopicOperation.PRODUCE));
        assertTrue(topicOp(admin, TOPIC_PATH, TopicOperation.CONSUME));

        String role = support.authed(support.attenuate(rootBiscuit, topicOperationCheck(TopicName.get(TOPIC_PATH), TopicOperation.CONSUME)));
        assertFalse(topicOp(role, TOPIC_PATH, TopicOperation.PRODUCE));
        assertTrue(topicOp(role, TOPIC_PATH, TopicOperation.CONSUME));
    }

    @Test
    public void testTopicCreation() throws Exception {
        // biscuit allowing the "create topic" operation anywhere
        Biscuit rootBiscuit = support.adminBiscuit("check if namespace_operation(\"create_topic\")");
        String role = support.authed(rootBiscuit);
        assertTrue(namespaceOp(role, NS, NamespaceOperation.CREATE_TOPIC));
        assertFalse(namespaceOp(role, NS, NamespaceOperation.DELETE_TOPIC));
        assertTrue(namespaceOp(role, TENANT + "/namespace123", NamespaceOperation.CREATE_TOPIC));
        assertFalse(namespaceOp(role, TENANT + "/namespace123", NamespaceOperation.DELETE_TOPIC));
        assertTrue(namespaceOp(role, "tenant123/" + NAMESPACE, NamespaceOperation.CREATE_TOPIC));
        assertFalse(namespaceOp(role, "tenant123/" + NAMESPACE, NamespaceOperation.DELETE_TOPIC));

        // attenuate it to a single tenant/namespace
        String attenuated = support.authed(support.attenuate(rootBiscuit, "check if " + namespaceFact(TENANT, NAMESPACE)));
        assertTrue(namespaceOp(attenuated, NS, NamespaceOperation.CREATE_TOPIC));
        assertFalse(namespaceOp(attenuated, NS, NamespaceOperation.DELETE_TOPIC));
        assertFalse(namespaceOp(attenuated, TENANT + "/namespace123", NamespaceOperation.CREATE_TOPIC));
        assertFalse(namespaceOp(attenuated, TENANT + "/namespace123", NamespaceOperation.DELETE_TOPIC));
        assertFalse(namespaceOp(attenuated, "tenant123/" + NAMESPACE, NamespaceOperation.CREATE_TOPIC));
        assertFalse(namespaceOp(attenuated, "tenant123/" + NAMESPACE, NamespaceOperation.DELETE_TOPIC));
    }

    @Test
    public void testReadWriteTopicInNamespace() throws Exception {
        String role = support.authed(support.adminBiscuit("check if " + topicVariableFact(NamespaceName.get(NS)) + ", topic_operation($operation), [\"produce\",\"consume\"].contains($operation)"));

        assertTrue(topicOp(role, NS + "/test", TopicOperation.CONSUME));
        assertTrue(topicOp(role, NS + "/test123", TopicOperation.CONSUME));
        assertTrue(topicOp(role, NS + "/test", TopicOperation.PRODUCE));
        assertTrue(topicOp(role, NS + "/test123", TopicOperation.PRODUCE));
        assertFalse(topicOp(role, TENANT + "/namespace123/test123", TopicOperation.PRODUCE));
        assertFalse(topicOp(role, "tenant123/" + NAMESPACE + "/test123", TopicOperation.PRODUCE));

        // any other operation requires more rights
        assertFalse(namespaceOp(role, NS, NamespaceOperation.DELETE_TOPIC));
    }

    @Test
    public void testTopicOperation() throws Exception {
        String role = support.authed(support.attenuate(support.adminBiscuit(), "check if " + topicVariableFact(TENANT, NAMESPACE) + ", topic_operation($4)"));

        assertTrue(topicOp(role, NS + "/test", TopicOperation.PRODUCE));
        assertTrue(topicOp(role, NS + "/test", TopicOperation.CONSUME));

        // any other operation requires more rights
        assertFalse(namespaceOp(role, NS, NamespaceOperation.DELETE_TOPIC));
    }

    @Test
    public void testLimitations() throws Exception {
        String role = support.authed(support.attenuate(support.adminBiscuit(), namespaceScope()));

        assertTrue(namespacePolicy(role, NS, PolicyName.COMPACTION, PolicyOperation.WRITE));
        assertTrue(namespaceOp(role, NS, NamespaceOperation.CREATE_TOPIC));
        assertTrue(namespaceOp(role, NS, NamespaceOperation.GET_TOPIC));
        assertTrue(namespaceOp(role, NS, NamespaceOperation.GET_TOPICS));
        assertTrue(namespaceOp(role, NS, NamespaceOperation.DELETE_TOPIC));
        assertFalse(namespaceOp(role, TENANT + "/random-ns", NamespaceOperation.DELETE_TOPIC));
        assertFalse(namespaceOp(role, "random-tenant/" + NAMESPACE, NamespaceOperation.DELETE_TOPIC));
        assertFalse(namespaceOp(role, NS, NamespaceOperation.ADD_BUNDLE));
        assertFalse(namespaceOp(role, NS, NamespaceOperation.DELETE_BUNDLE));
        assertTrue(namespaceOp(role, NS, NamespaceOperation.GET_BUNDLE));
        assertTrue(namespaceOp(role, NS, NamespaceOperation.CLEAR_BACKLOG));
        assertTrue(namespaceOp(role, NS, NamespaceOperation.UNSUBSCRIBE));
        assertTrue(namespacePolicy(role, NS, PolicyName.ALL, PolicyOperation.READ));
        assertTrue(namespacePolicy(role, NS, PolicyName.TTL, PolicyOperation.READ));
        assertFalse(namespacePolicy(role, NS, PolicyName.OFFLOAD, PolicyOperation.WRITE));
        assertTrue(namespacePolicy(role, NS, PolicyName.SCHEMA_COMPATIBILITY_STRATEGY, PolicyOperation.WRITE));
        assertFalse(namespacePolicy(role, NS, PolicyName.REPLICATION, PolicyOperation.WRITE));
        assertTrue(namespacePolicy(role, NS, PolicyName.REPLICATION, PolicyOperation.READ));

        AuthenticationDataSource noSubscription = new AuthenticationDataSource() {
            @Override
            public String getSubscription() {
                return null;
            }
        };
        assertTrue(topicOp(role, NS + "/test", TopicOperation.LOOKUP));
        assertFalse(topicOp(role, TENANT + "/random-ns/test", TopicOperation.LOOKUP));
        assertFalse(topicOp(role, "random-tenant/random-ns/test", TopicOperation.CONSUME, noSubscription));
        assertTrue(topicOp(role, NS + "/test", TopicOperation.CONSUME, noSubscription));
        assertTrue(topicOp(role, NS + "/test", TopicOperation.PRODUCE));
        assertTrue(topicOp(role, NS + "/test123", TopicOperation.CONSUME, noSubscription));
        assertTrue(topicOp(role, NS + "/test123", TopicOperation.PRODUCE));
        assertTrue(topicPolicy(role, NS + "/test", PolicyName.ALL, PolicyOperation.READ));
        assertFalse(topicPolicy(role, NS + "/test", PolicyName.ALL, PolicyOperation.WRITE));

        assertFalse(provider.isSuperUser(role, null, support.conf()).get());
    }

    @Test
    public void testClusterAndBrokerOperationsAreSuperUserOnly() throws Exception {
        Biscuit rootBiscuit = support.adminBiscuit();
        String admin = support.authed(rootBiscuit);
        String tenant = support.authed(support.attenuate(rootBiscuit, namespaceScope()));

        assertTrue(provider.allowClusterOperationAsync("cluster", ClusterOperation.GET_CLUSTER, admin, null).get());
        assertTrue(provider.allowClusterPolicyOperationAsync("cluster", admin, PolicyName.NAMESPACE_ISOLATION, PolicyOperation.WRITE, null).get());
        assertTrue(provider.allowBrokerOperationAsync("cluster", "broker-1", BrokerOperation.LIST_OWNED_NAMESPACES, admin, null).get());

        assertFalse(provider.allowClusterOperationAsync("cluster", ClusterOperation.GET_CLUSTER, tenant, null).get());
        assertFalse(provider.allowClusterPolicyOperationAsync("cluster", tenant, PolicyName.NAMESPACE_ISOLATION, PolicyOperation.READ, null).get());
        assertFalse(provider.allowBrokerOperationAsync("cluster", "broker-1", BrokerOperation.LIST_OWNED_NAMESPACES, tenant, null).get());
    }

    @Test
    public void testPulsar4PolicyNamesStayReadOnlyForTenants() throws Exception {
        String role = support.authed(support.attenuate(support.adminBiscuit(), namespaceScope()));

        // policy names added by Pulsar 4.x: readable, never writable by an attenuated token
        for (PolicyName policy : new PolicyName[]{PolicyName.DISPATCHER_PAUSE_ON_ACK_STATE_PERSISTENT, PolicyName.ALLOW_CLUSTERS, PolicyName.ALLOW_CUSTOM_METRIC_LABELS, PolicyName.CLUSTER_MIGRATION, PolicyName.NAMESPACE_ISOLATION}) {
            assertTrue(policy.name(), namespacePolicy(role, NS, policy, PolicyOperation.READ));
            assertTrue(policy.name(), topicPolicy(role, NS + "/test", policy, PolicyOperation.READ));
            assertFalse(policy.name(), namespacePolicy(role, NS, policy, PolicyOperation.WRITE));
            assertFalse(policy.name(), topicPolicy(role, NS + "/test", policy, PolicyOperation.WRITE));
        }
    }

    private PulsarAuthorizationProvider mockDefaultProvider() throws Exception {
        PulsarAuthorizationProvider defaultProvider = mock(PulsarAuthorizationProvider.class);
        Field field = AuthorizationProviderBiscuit.class.getDeclaredField("defaultProvider");
        field.setAccessible(true);
        field.set(provider, defaultProvider);
        return defaultProvider;
    }

    @Test
    public void testNonBiscuitRolesDelegateToDefaultProvider() throws Exception {
        PulsarAuthorizationProvider defaultProvider = mockDefaultProvider();

        // a non-biscuit role (e.g. JWT) reaches the default provider on the 4.x hooks and on isSuperUser
        String jwtRole = "jwt-user";
        when(defaultProvider.allowClusterOperationAsync("cluster", ClusterOperation.GET_CLUSTER, jwtRole, null)).thenReturn(CompletableFuture.completedFuture(true));
        when(defaultProvider.allowClusterPolicyOperationAsync("cluster", jwtRole, PolicyName.NAMESPACE_ISOLATION, PolicyOperation.READ, null)).thenReturn(CompletableFuture.completedFuture(true));
        when(defaultProvider.allowBrokerOperationAsync("cluster", "broker-1", BrokerOperation.LIST_BROKERS, jwtRole, null)).thenReturn(CompletableFuture.completedFuture(true));
        when(defaultProvider.isSuperUser(jwtRole, null, null)).thenReturn(CompletableFuture.completedFuture(false));
        assertTrue(provider.allowClusterOperationAsync("cluster", ClusterOperation.GET_CLUSTER, jwtRole, null).get());
        assertTrue(provider.allowClusterPolicyOperationAsync("cluster", jwtRole, PolicyName.NAMESPACE_ISOLATION, PolicyOperation.READ, null).get());
        assertTrue(provider.allowBrokerOperationAsync("cluster", "broker-1", BrokerOperation.LIST_BROKERS, jwtRole, null).get());
        assertFalse(provider.isSuperUser(jwtRole, null, null).get());
    }

    private static void assertRefused(CompletableFuture<?> future) {
        ExecutionException refused = assertThrows(ExecutionException.class, future::get);
        assertEquals(AuthorizationProviderBiscuit.PERMISSION_MANAGEMENT_DISABLED, refused.getCause().getMessage());
    }

    @Test
    public void testPulsarPermissionManagementIsRefusedAndNeverStored() throws Exception {
        PulsarAuthorizationProvider defaultProvider = mockDefaultProvider();
        String role = "someone";
        NamespaceName ns = NamespaceName.get(NS);
        TopicName topic = TopicName.get(NS + "/test");

        // every write is refused, whatever the caller, and never reaches Pulsar's permission store
        assertRefused(provider.grantPermissionAsync(ns, Set.of(AuthAction.produce), role, null));
        assertRefused(provider.grantPermissionAsync(topic, Set.of(AuthAction.produce), role, null));
        assertRefused(provider.grantPermissionAsync(List.<GrantTopicPermissionOptions>of()));
        assertRefused(provider.grantSubscriptionPermissionAsync(ns, "sub", Set.of(role), null));
        assertRefused(provider.revokePermissionAsync(ns, role));
        assertRefused(provider.revokePermissionAsync(topic, role));
        assertRefused(provider.revokePermissionAsync(List.<RevokeTopicPermissionOptions>of()));
        assertRefused(provider.revokeSubscriptionPermissionAsync(ns, "sub", role, null));
        // topic deletion has nothing to clean up
        assertNull(provider.removePermissionsAsync(topic).get());
        verifyNoInteractions(defaultProvider);

        // reads stay truthful, so a leftover ACL remains visible
        CompletableFuture<Map<String, Set<AuthAction>>> nsPermissions = CompletableFuture.completedFuture(Map.of("legacy", Set.of(AuthAction.consume)));
        CompletableFuture<Map<String, Set<AuthAction>>> topicPermissions = CompletableFuture.completedFuture(Map.of());
        CompletableFuture<Map<String, Set<String>>> subscriptionPermissions = CompletableFuture.completedFuture(Map.of());
        when(defaultProvider.getPermissionsAsync(ns)).thenReturn(nsPermissions);
        when(defaultProvider.getPermissionsAsync(topic)).thenReturn(topicPermissions);
        when(defaultProvider.getSubscriptionPermissionsAsync(ns)).thenReturn(subscriptionPermissions);
        assertSame(nsPermissions, provider.getPermissionsAsync(ns));
        assertSame(topicPermissions, provider.getPermissionsAsync(topic));
        assertSame(subscriptionPermissions, provider.getSubscriptionPermissionsAsync(ns));
    }

    private static ServiceConfiguration confWith(String... keyValues) {
        Properties properties = new Properties();
        for (int i = 0; i < keyValues.length; i += 2) {
            properties.setProperty(keyValues[i], keyValues[i + 1]);
        }
        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        return conf;
    }

    @Test
    public void testRunLimitsAreReadFromConfWithDefaultsForAbsentOrBlankKeys() throws Exception {
        PulsarResources resources = mock(PulsarResources.class);
        AuthorizationProviderBiscuit fresh = new AuthorizationProviderBiscuit();

        fresh.initialize(confWith(
                AuthorizationProviderBiscuit.CONF_BISCUIT_RUNLIMITS_MAX_FACTS, "5000",
                AuthorizationProviderBiscuit.CONF_BISCUIT_RUNLIMITS_MAX_ITERATIONS, " 250 ",
                AuthorizationProviderBiscuit.CONF_BISCUIT_RUNLIMITS_MAX_TIME, "30"), resources);
        assertEquals(5000, fresh.runLimits().maxFacts);
        assertEquals(250, fresh.runLimits().maxIterations);
        assertEquals(Duration.ofMillis(30), fresh.runLimits().maxTime);

        // a second initialize with blank (broker.conf "key=") and absent keys falls back to the defaults,
        // not to the values of the previous call
        fresh.initialize(confWith(
                AuthorizationProviderBiscuit.CONF_BISCUIT_RUNLIMITS_MAX_FACTS, "",
                AuthorizationProviderBiscuit.CONF_BISCUIT_RUNLIMITS_MAX_TIME, "  "), resources);
        assertEquals(AuthorizationProviderBiscuit.DEFAULT_RUNLIMITS_MAX_FACTS, fresh.runLimits().maxFacts);
        assertEquals(AuthorizationProviderBiscuit.DEFAULT_RUNLIMITS_MAX_ITERATIONS, fresh.runLimits().maxIterations);
        assertEquals(Duration.ofMillis(AuthorizationProviderBiscuit.DEFAULT_RUNLIMITS_MAX_TIME_MILLIS), fresh.runLimits().maxTime);
    }

    @Test
    public void testSuperUser() throws Exception {
        String admin = support.authed(support.adminBiscuit());

        assertTrue(provider.isSuperUser(admin, null, support.conf()).get());
        assertTrue(namespacePolicy(admin, "randomTenant/randomNamespace", PolicyName.REPLICATION, PolicyOperation.WRITE));
    }

    @Test
    public void testNsLimitationsThenPrefixLimitation() throws Exception {
        String prefix = "INSTANCE_PREFIX_TO_DEFINE";
        // limit to the namespace, then to tenant/namespace/PREFIX*
        Biscuit biscuit = support.attenuate(support.adminBiscuit(), namespaceScope());
        biscuit = support.attenuate(biscuit, "check if " + topicVariableFact(TENANT, NAMESPACE) + ", $topic.starts_with(\"" + prefix + "\")");
        String role = support.authed(biscuit);

        assertFalse(topicOp(role, NS + "/test", TopicOperation.PRODUCE));
        assertTrue(topicOp(role, NS + "/" + prefix, TopicOperation.PRODUCE));
        assertTrue(topicOp(role, NS + "/" + prefix + "-concat", TopicOperation.PRODUCE));
    }

    @Test
    public void testLimitProduceOnTopicStartsWith() throws Exception {
        String prefix = "PREFIX";
        // limit to produce on tenant/namespace/PREFIX*
        String role = support.authed(support.attenuate(support.adminBiscuit(), "check if " + topicVariableFact(TENANT, NAMESPACE) + "," + topicOperationFact(TopicOperation.PRODUCE) + ", $topic.starts_with(\"" + prefix + "\")"));

        assertFalse(topicOp(role, NS + "/test", TopicOperation.PRODUCE));
        assertTrue(topicOp(role, NS + "/" + prefix, TopicOperation.PRODUCE));
        assertTrue(topicOp(role, NS + "/" + prefix + "-concat", TopicOperation.PRODUCE));
        assertFalse(topicOp(role, NS + "/test", TopicOperation.CONSUME));
        assertFalse(topicOp(role, NS + "/" + prefix, TopicOperation.CONSUME));
        assertFalse(topicOp(role, NS + "/" + prefix + "-concat", TopicOperation.CONSUME));
    }

    @Test
    public void testConsumeOverrideLookup() throws Exception {
        String role = support.authed(support.attenuate(support.adminBiscuit(), "check if " + topicVariableFact(TENANT, NAMESPACE) + "," + topicOperationFact(TopicOperation.CONSUME)));

        assertTrue(topicOp(role, NS + "/test", TopicOperation.LOOKUP));
        assertTrue(topicOp(role, NS + "/test", TopicOperation.CONSUME));
        assertFalse(topicOp(role, TENANT + "/namespaceForbidden/test", TopicOperation.LOOKUP));
        assertFalse(topicOp(role, TENANT + "/namespaceForbidden/test", TopicOperation.PRODUCE));
        assertFalse(topicOp(role, "tenantForbidden/" + NAMESPACE + "/test", TopicOperation.LOOKUP));
        assertFalse(topicOp(role, "tenantForbidden/" + NAMESPACE + "/test", TopicOperation.PRODUCE));
    }

    @Test
    public void testProduceOverrideLookup() throws Exception {
        String role = support.authed(support.attenuate(support.adminBiscuit(), "check if " + topicVariableFact(TENANT, NAMESPACE) + "," + topicOperationFact(TopicOperation.PRODUCE)));

        assertTrue(topicOp(role, NS + "/test", TopicOperation.LOOKUP));
        assertTrue(topicOp(role, NS + "/test", TopicOperation.PRODUCE));
        assertFalse(topicOp(role, TENANT + "/namespaceForbidden/test", TopicOperation.LOOKUP));
        assertFalse(topicOp(role, TENANT + "/namespaceForbidden/test", TopicOperation.PRODUCE));
        assertFalse(topicOp(role, "tenantForbidden/" + NAMESPACE + "/test", TopicOperation.LOOKUP));
        assertFalse(topicOp(role, "tenantForbidden/" + NAMESPACE + "/test", TopicOperation.PRODUCE));
    }

    @Test
    public void testLookupIsNotOverrodeByProduceOrConsume() throws Exception {
        String role = support.authed(support.attenuate(support.adminBiscuit(), "check if " + topicVariableFact(TENANT, NAMESPACE) + "," + topicOperationFact(TopicOperation.LOOKUP)));

        assertLookupOnly(role);
    }

    @Test
    public void testLookupIsNotOverrodeByProduceOrConsumeWithBiscuitV3Compatibility() throws Exception {
        BiscuitTestSupport fixedRoot = BiscuitTestSupport.withRoot("005248AE3870664EFC914A287BD2DB70626316E2CD004FA138837E8430D9A5CF");

        // biscuit generated with biscuit-java v3.0.1 of the testLookupIsNotOverrodeByProduceOrConsume test
        Biscuit biscuit = Biscuit.from_b64url("EnYKDBgDIggKBggEEgIYDRIkCAASIOHcyKojONtsqsY1UjQQTQ3u3RT6b3lEYQ3qzBEemeaWGkDFlr56tGlo-Z1RloR1nScE13xMJWoOspcB5UP1FJ0Lt_0FCD4_3pccskLgDntQHAxc3ugF6Db8k4uUjs3EqJkLGs0BCmMKBXRvcGljCgp0ZW5hbnRUZXN0Cg1uYW1lc3BhY2VUZXN0Cg90b3BpY19vcGVyYXRpb24KBmxvb2t1cBgDMiQKIgoCCBsSEgiACBIDGIEIEgMYgggSAwiACBIICIMIEgMYhAgSJAgAEiAdRHtivWCRZ9IhUui2vkCFtCnCOQoGlgZ3QN1DAEc3BhpAI8SI62pQde-ZIjFX6qDV5rd-94_SRAk7EVGHmoY58ulf04dDX7jN4hIu28DE0Q0p3ebRxOwhuCCgabZl_NktBSIiCiAAUkiuOHBmTvyRSih70ttwYmMW4s0AT6E4g36EMNmlzw==", fixedRoot.root.public_key());
        String role = fixedRoot.authed(biscuit);

        assertLookupOnly(role);
    }

    private void assertLookupOnly(String role) throws Exception {
        assertTrue(topicOp(role, NS + "/test", TopicOperation.LOOKUP));
        assertFalse(topicOp(role, TENANT + "/namespaceForbidden/test", TopicOperation.LOOKUP));
        assertFalse(topicOp(role, "tenantForbidden/" + NAMESPACE + "/test", TopicOperation.LOOKUP));
        assertFalse(topicOp(role, NS + "/test", TopicOperation.PRODUCE));
        assertFalse(topicOp(role, NS + "/test", TopicOperation.CONSUME));
    }

    /** Root → one namespace → consume on one topic of it. */
    private String consumeOnTopicOnly() throws Exception {
        Biscuit namespaceOnly = support.attenuate(support.adminBiscuit(), namespaceScope());
        return support.authed(support.attenuate(namespaceOnly, "check if " + topicFact(TopicName.get(TOPIC_PATH)) + "," + topicOperationFact(TopicOperation.CONSUME)));
    }

    @Test
    public void testAuthorizeConsumptionOnSpecifiedTopic() throws Exception {
        String role = consumeOnTopicOnly();

        assertTrue(topicOp(role, TOPIC_PATH, TopicOperation.CONSUME));
        assertFalse(topicOp(role, TENANT + "/namespaceForbidden/" + TOPIC, TopicOperation.PRODUCE));
        assertFalse(topicOp(role, "tenantForbidden/" + NAMESPACE + "/topicForbidden", TopicOperation.PRODUCE));
        assertFalse(topicOp(role, "tenantForbidden/" + NAMESPACE + "/" + TOPIC, TopicOperation.PRODUCE));
    }

    @Test
    public void testAuthorizeConsumptionOnSpecifiedTopicPartioned() throws Exception {
        String role = consumeOnTopicOnly();

        String partitioned = TOPIC + "-partition-0";
        assertTrue(topicOp(role, NS + "/" + partitioned, TopicOperation.CONSUME));
        assertFalse(topicOp(role, TENANT + "/namespaceForbidden/" + partitioned, TopicOperation.PRODUCE));
        assertFalse(topicOp(role, "tenantForbidden/" + NAMESPACE + "/topicForbidden-partition-0", TopicOperation.PRODUCE));
        assertFalse(topicOp(role, "tenantForbidden/" + NAMESPACE + "/" + partitioned, TopicOperation.PRODUCE));
    }

    @Test
    public void testConsumeOnTopicWithAuthorizedSubscription() throws Exception {
        String subscription = "subNameTest";
        String role = support.authed(support.adminBiscuit(topicOperationCheck(TopicName.get(TOPIC_PATH), TopicOperation.CONSUME, subscription)));

        assertFalse(topicOp(role, TOPIC_PATH, TopicOperation.PRODUCE, subscription(subscription)));
        assertTrue(topicOp(role, TOPIC_PATH, TopicOperation.CONSUME, subscription(subscription)));
    }

    @Test
    public void testConsumeOnTopicWithUnauthorizedSubscription() throws Exception {
        String role = support.authed(support.adminBiscuit(topicOperationCheck(TopicName.get(TOPIC_PATH), TopicOperation.CONSUME, "subNameTest")));

        assertFalse(topicOp(role, TOPIC_PATH, TopicOperation.PRODUCE, subscription("wrongSubscriptionName")));
        assertFalse(topicOp(role, TOPIC_PATH, TopicOperation.CONSUME, subscription("wrongSubscriptionName")));
    }
}
