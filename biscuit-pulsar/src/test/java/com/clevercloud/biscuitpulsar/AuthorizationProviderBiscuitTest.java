package com.clevercloud.biscuitpulsar;

import com.clevercloud.biscuit.crypto.KeyPair;
import com.clevercloud.biscuit.datalog.SymbolTable;
import com.clevercloud.biscuit.token.Biscuit;
import com.clevercloud.biscuit.token.builder.Block;
import com.clevercloud.biscuit.token.builder.Caveat;
import com.clevercloud.biscuit.token.builder.constraints.StrConstraint;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.common.naming.NamespaceName;
import org.apache.pulsar.common.naming.TopicName;
import org.apache.pulsar.common.policies.data.NamespaceOperation;
import org.apache.pulsar.common.policies.data.PolicyName;
import org.apache.pulsar.common.policies.data.PolicyOperation;
import org.apache.pulsar.common.policies.data.TopicOperation;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.lang.reflect.Array;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static com.clevercloud.biscuit.crypto.TokenSignature.hex;
import static com.clevercloud.biscuit.token.builder.Utils.*;
import static org.junit.Assert.*;

public class AuthorizationProviderBiscuitTest {
    private static final Logger log = LoggerFactory.getLogger(AuthorizationProviderBiscuitTest.class);

    @Test
    public void testTopicCreation() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_rule(rule("right",
            Arrays.asList(s("authority"), string(tenant), string(namespace), s("create_topic")),
            Arrays.asList(pred("namespace_operation", Arrays.asList(s("ambient"), string(tenant), string(namespace), s("create_topic"))))));
        Biscuit biscuit = Biscuit.make(rng, root, symbols, authority_builder.build()).get();

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_SEALING_KEY, "test");
        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);
        String authedBiscuit = provider.authenticate(new AuthenticationDataSource() {
            @Override
            public boolean hasDataFromCommand() {
                return true;
            }

            @Override
            public String getCommandData() {
                return biscuit.serialize_b64().get();
            }
        });

        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        log.debug(biscuit.print());
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace),  authedBiscuit, NamespaceOperation.CREATE_TOPIC, null));
    }

    @Test
    public void testReadWriteTopicInNamespace() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), string(tenant), string(namespace), s("create_topic")),
                Arrays.asList(pred("namespace_operation", Arrays.asList(s("ambient"), string(tenant), string(namespace), s("create_topic"))))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), string(tenant), string(namespace), var(2), s("produce")),
                Arrays.asList(pred("topic_operation", Arrays.asList(s("ambient"), string(tenant), string(namespace), var(2), s("produce"))))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), string(tenant), string(namespace), var(2), s("consume")),
                Arrays.asList(pred("topic_operation", Arrays.asList(s("ambient"), string(tenant), string(namespace), var(2), s("consume"))))));
        Biscuit biscuit = Biscuit.make(rng, root, symbols, authority_builder.build()).get();

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_SEALING_KEY, "test");
        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);
        String authedBiscuit = provider.authenticate(new AuthenticationDataSource() {
            @Override
            public boolean hasDataFromCommand() {
                return true;
            }

            @Override
            public String getCommandData() {
                return biscuit.serialize_b64().get();
            }
        });

        log.debug(biscuit.print());
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.CREATE_TOPIC, null));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.CONSUME, null));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + "test123"), authedBiscuit, TopicOperation.CONSUME, null));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.PRODUCE, null));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + "test123"), authedBiscuit, TopicOperation.PRODUCE, null));
    }

    @Test
    public void testTopicOperation() throws IOException, AuthenticationException, ExecutionException, InterruptedException {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_fact(fact("revocation_id", Arrays.asList(date(Date.from(Instant.now())))));
        authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s("admin"))));
        Biscuit rootBiscuit = Biscuit.make(rng, root, symbols, authority_builder.build()).get();

        Block block = rootBiscuit.create_block();
        block.add_caveat(new Caveat(Arrays.asList(
                rule("limited_right",
                        Arrays.asList(string(tenant), string(namespace), var(2), var(3)),
                        Arrays.asList(pred("topic_operation", Arrays.asList(s("ambient"), string(tenant), string(namespace), var(2), var(3))))),
                rule("limited_right",
                        Arrays.asList(string(tenant), string(namespace), var(2)),
                        Arrays.asList(pred("namespace_operation", Arrays.asList(s("ambient"), string(tenant), string(namespace), var(2)))))
        )));

        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block.build()).get();

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_SEALING_KEY, "test");
        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);
        String authedBiscuit = provider.authenticate(new AuthenticationDataSource() {
            @Override
            public boolean hasDataFromCommand() {
                return true;
            }

            @Override
            public String getCommandData() {
                return biscuit.serialize_b64().get();
            }
        });

        log.debug(biscuit.print());
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.CONSUME, null).get());
    }

    @Test
    public void testNsLimitations() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_fact(fact("revocation_id", Arrays.asList(date(Date.from(Instant.now())))));
        authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s("admin"))));
        Biscuit rootBiscuit = Biscuit.make(rng, root, symbols, authority_builder.build()).get();

        Block block = rootBiscuit.create_block();
        block.add_caveat(new Caveat(Arrays.asList(
            rule("limited_right",
                    Arrays.asList(string(tenant), string(namespace), var(2), var(3)),
                    Arrays.asList(pred("topic_operation", Arrays.asList(s("ambient"), string(tenant), string(namespace), var(2), var(3))))),
            rule("limited_right",
                    Arrays.asList(string(tenant), string(namespace), var(2)),
                    Arrays.asList(pred("namespace_operation", Arrays.asList(s("ambient"), string(tenant), string(namespace), var(2)))))
        )));

        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block.build()).get();
        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_SEALING_KEY, "test");
        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);
        String authedBiscuit = provider.authenticate(new AuthenticationDataSource() {
            @Override
            public boolean hasDataFromCommand() {
                return true;
            }

            @Override
            public String getCommandData() {
                return biscuit.serialize_b64().get();
            }
        });

        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();

        log.debug(biscuit.print());
        assertTrue(authorizationProvider.allowNamespacePolicyOperation(NamespaceName.get(tenant + "/" + namespace), PolicyName.COMPACTION, PolicyOperation.WRITE,  authedBiscuit, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.CREATE_TOPIC, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.GET_TOPIC, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.GET_TOPICS, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.DELETE_TOPIC, null));
        assertFalse(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/random-ns"), authedBiscuit, NamespaceOperation.DELETE_TOPIC, null));
        assertFalse(authorizationProvider.allowNamespaceOperation(NamespaceName.get("random-tenant/" + namespace), authedBiscuit, NamespaceOperation.DELETE_TOPIC, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.ADD_BUNDLE, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.DELETE_BUNDLE, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace),  authedBiscuit, NamespaceOperation.GET_BUNDLE, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace),  authedBiscuit, NamespaceOperation.CLEAR_BACKLOG, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace),  authedBiscuit, NamespaceOperation.UNSUBSCRIBE, null));
        assertTrue(authorizationProvider.allowNamespacePolicyOperation(NamespaceName.get(tenant + "/" + namespace), PolicyName.ALL, PolicyOperation.READ,  authedBiscuit, null));
        assertTrue(authorizationProvider.allowNamespacePolicyOperation(NamespaceName.get(tenant + "/" + namespace), PolicyName.TTL, PolicyOperation.READ,  authedBiscuit, null));
        assertFalse(authorizationProvider.allowNamespacePolicyOperation(NamespaceName.get(tenant + "/" + namespace), PolicyName.OFFLOAD, PolicyOperation.WRITE,  authedBiscuit, null));
        assertTrue(authorizationProvider.allowNamespacePolicyOperation(NamespaceName.get(tenant + "/" + namespace), PolicyName.SCHEMA_COMPATIBILITY_STRATEGY, PolicyOperation.WRITE,  authedBiscuit, null));
        assertFalse(authorizationProvider.allowNamespacePolicyOperation(NamespaceName.get(tenant + "/" + namespace), PolicyName.REPLICATION, PolicyOperation.WRITE,  authedBiscuit, null));
        assertTrue(authorizationProvider.allowNamespacePolicyOperation(NamespaceName.get(tenant + "/" + namespace), PolicyName.REPLICATION, PolicyOperation.READ,  authedBiscuit, null));
        AuthenticationDataSource authData = new AuthenticationDataSource() {
            @Override
            public String getSubscription() {
                return null;
            }
        };

        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + "test"),  authedBiscuit, TopicOperation.LOOKUP, null));
        assertFalse(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/random-ns/" + "test"),  authedBiscuit, TopicOperation.LOOKUP, null));
        assertFalse(authorizationProvider.allowTopicOperation(TopicName.get("random-tenant/random-ns/test"),  authedBiscuit, TopicOperation.CONSUME, authData));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + "test"),  authedBiscuit, TopicOperation.CONSUME, authData));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + "test"),  authedBiscuit, TopicOperation.PRODUCE, null));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + "test123"),  authedBiscuit, TopicOperation.CONSUME, authData));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + "test123"),  authedBiscuit, TopicOperation.PRODUCE, null));
        assertFalse(authorizationProvider.isSuperUser(authedBiscuit, null, conf).get());
    }

    @Test
    public void testBuilders() {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_fact(fact("revocation_id", Arrays.asList(date(Date.from(Instant.now())))));
        authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s("admin"))));
        authority_builder.add_rule(constrained_rule("right",
                Arrays.asList(s("authority"), s("namespace"), var(0), var(1), var(2)),
                Arrays.asList(pred("ns_operation", Arrays.asList(s("authority"), s("namespace"), var(0), var(1), var(2)))),
                Arrays.asList(new com.clevercloud.biscuit.token.builder.constraints.SymbolConstraint.InSet(2, new HashSet<>(Arrays.asList(
                        "create_topic",
                        "get_topic",
                        "get_topics"
                ))))
        ));
        authority_builder.add_rule(constrained_rule("right",
                Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), var(3)),
                Arrays.asList(pred("topic_operation", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), var(3)))),
                Arrays.asList(new com.clevercloud.biscuit.token.builder.constraints.SymbolConstraint.InSet(3, new HashSet<>(Arrays.asList(
                        "lookup"
                ))))
        ));

        Biscuit rootBiscuit = Biscuit.make(rng, root, symbols, authority_builder.build()).get();
        assertNotNull(rootBiscuit);
    }

    @Test
    public void testSuperUser() throws IOException, AuthenticationException, ExecutionException, InterruptedException {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_fact(fact("revocation_id", Arrays.asList(date(Date.from(Instant.now())))));
        authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s("admin"))));
        Biscuit biscuit = Biscuit.make(rng, root, symbols, authority_builder.build()).get();

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_SEALING_KEY, "test");
        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);
        String authedBiscuit = provider.authenticate(new AuthenticationDataSource() {
            @Override
            public boolean hasDataFromCommand() {
                return true;
            }
            @Override
            public String getCommandData() {
                return biscuit.serialize_b64().get();
            }
        });

        log.debug(biscuit.print());

        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        assertTrue(authorizationProvider.isSuperUser(authedBiscuit, null, conf).get());
    }

    @Test
    public void testSimpleSuperUser() throws IOException, AuthenticationException, ExecutionException, InterruptedException {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_rule(
                rule("right",
                        Arrays.asList(s("authority"), s("admin")),
                        Arrays.asList(pred("right", Arrays.asList(s("authority"), string("admin"))))
                )
        );
        authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s("admin"))));
        Biscuit biscuit = Biscuit.make(rng, root, symbols, authority_builder.build()).get();

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_SEALING_KEY, "test");
        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);
        String authedBiscuit = provider.authenticate(new AuthenticationDataSource() {
            @Override
            public boolean hasDataFromCommand() {
                return true;
            }
            @Override
            public String getCommandData() {
                return biscuit.serialize_b64().get();
            }
        });

        log.debug(biscuit.print());
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        CompletableFuture<Boolean> authorizedFuture = authorizationProvider.isSuperUser(authedBiscuit, null, conf);
        assertTrue(authorizedFuture.get());
    }

    @Test
    public void testNsLimitationsThenPrefixLimitation() throws IOException, AuthenticationException, ExecutionException, InterruptedException {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        // root token
        Block authority_builder = new Block(0, symbols);
        authority_builder.add_fact(fact("revocation_id", Arrays.asList(date(Date.from(Instant.now())))));
        authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s("admin"))));
        Biscuit rootBiscuit = Biscuit.make(rng, root, symbols, authority_builder.build()).get();

        // limit on ns tenant/namespace
        Block block = rootBiscuit.create_block();
        block.add_caveat(new Caveat(Arrays.asList(
                rule("limited_right",
                        Arrays.asList(string(tenant), string(namespace), var(2), var(3)),
                        Arrays.asList(pred("topic_operation", Arrays.asList(s("ambient"), string(tenant), string(namespace), var(2), var(3))))),
                rule("limited_right",
                        Arrays.asList(string(tenant), string(namespace), var(2)),
                        Arrays.asList(pred("namespace_operation", Arrays.asList(s("ambient"), string(tenant), string(namespace), var(2)))))
        )));
        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block.build()).get();

        // limit on tenant/namespace/PREFIX*
        String PREFIX = "INSTANCE_PREFIX_TO_DEFINE";
        Block attenuated = biscuit.create_block();
        attenuated.add_caveat(caveat(constrained_rule("limited_topic",
                Arrays.asList(string(tenant), string(namespace), var(2)),
                Arrays.asList(pred("topic_operation", Arrays.asList(s("ambient"), string(tenant), string(namespace), var(2), var(3)))),
                Arrays.asList(new StrConstraint.Prefix(2, PREFIX))
        )));
        biscuit = biscuit.attenuate(rng, root, attenuated.build()).get();

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_SEALING_KEY, "test");
        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);
        Biscuit finalBiscuit = biscuit;
        String authedBiscuit = provider.authenticate(new AuthenticationDataSource() {
            @Override
            public boolean hasDataFromCommand() {
                return true;
            }
            @Override
            public String getCommandData() {
                return finalBiscuit.serialize_b64().get();
            }
        });

        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();

        log.debug(biscuit.print());
        assertFalse(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/test"),  authedBiscuit, TopicOperation.PRODUCE, null));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + PREFIX),  authedBiscuit, TopicOperation.PRODUCE, null));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + PREFIX + "-concat"),  authedBiscuit, TopicOperation.PRODUCE, null));
    }

    @Test
    public void testLimitProduceOnTopicStartsWith() throws IOException, AuthenticationException, ExecutionException, InterruptedException {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        // root token
        Block authority_builder = new Block(0, symbols);
        authority_builder.add_fact(fact("revocation_id", Arrays.asList(string(UUID.randomUUID().toString()))));
        authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s("admin"))));
        Biscuit rootBiscuit = Biscuit.make(rng, root, symbols, authority_builder.build()).get();

        // limit on tenant/namespace/PREFIX*
        String PREFIX = "PREFIX";
        Block attenuated = rootBiscuit.create_block();
        attenuated.add_caveat(caveat(constrained_rule("limited_topic",
                Arrays.asList(string(tenant), string(namespace), var(2)),
                Arrays.asList(pred("topic_operation", Arrays.asList(s("ambient"), string(tenant), string(namespace), var(2), s("produce")))),
                Arrays.asList(new StrConstraint.Prefix(2, PREFIX))
        )));
        Biscuit biscuit = rootBiscuit.attenuate(rng, root, attenuated.build()).get();

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_SEALING_KEY, "test");
        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);
        Biscuit finalBiscuit = biscuit;
        String authedBiscuit = provider.authenticate(new AuthenticationDataSource() {
            @Override
            public boolean hasDataFromCommand() {
                return true;
            }
            @Override
            public String getCommandData() {
                return finalBiscuit.serialize_b64().get();
            }
        });

        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();

        log.debug(biscuit.print());
        assertFalse(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/test"),  authedBiscuit, TopicOperation.PRODUCE, null));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + PREFIX),  authedBiscuit, TopicOperation.PRODUCE, null));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + PREFIX + "-concat"),  authedBiscuit, TopicOperation.PRODUCE, null));
        assertFalse(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/test"),  authedBiscuit, TopicOperation.CONSUME, null));
        assertFalse(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + PREFIX),  authedBiscuit, TopicOperation.CONSUME, null));
        assertFalse(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + PREFIX + "-concat"),  authedBiscuit, TopicOperation.CONSUME, null));
    }
}
