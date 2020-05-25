package com.clevercloud.biscuitpulsar;

import com.clevercloud.biscuit.crypto.KeyPair;
import com.clevercloud.biscuit.datalog.SymbolTable;
import com.clevercloud.biscuit.token.Biscuit;
import com.clevercloud.biscuit.token.builder.Block;
import com.clevercloud.biscuit.token.builder.Caveat;
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
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static com.clevercloud.biscuit.crypto.TokenSignature.hex;
import static com.clevercloud.biscuit.token.builder.Utils.*;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AuthorizationProviderBiscuitTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationProviderBiscuitTest.class);

    private com.clevercloud.biscuit.token.builder.Fact topic(TopicName topicName) {
        return fact("topic", Arrays.asList(s("ambient"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName())));
    }

    private com.clevercloud.biscuit.token.builder.Fact subscription(TopicName topicName, String subscription) {
        return fact("subscription", Arrays.asList(s("ambient"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), string(subscription)));
    }

    private com.clevercloud.biscuit.token.builder.Predicate topicRight(TopicName topicName, String right) {
        return pred("right", Arrays.asList(s("authority"), s("topic"),
                string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), s(right)));
    }

    @Test
    public void testTopicCreation() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_rule(
                rule("right",
                        Arrays.asList(s("authority"), s("namespace"), string(tenant), string(namespace), s("create_topic")),
                        Arrays.asList(pred("namespace", Arrays.asList(s("ambient"), string(tenant), string(namespace))))
                )
        );
        authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s(namespace), string(tenant), string(namespace), s("create_topic"))));
        Biscuit biscuit = Biscuit.make(rng, root, symbols, authority_builder.build()).get();

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));
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
        Boolean authorized = authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.CREATE_TOPIC, null);
        assertTrue(authorized);
    }

    @Test
    public void testReadWriteTopicInNamespace() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_rule(
                rule("right",
                        Arrays.asList(s("authority"), s("namespace"), string(tenant), string(namespace), s("create_topic")),
                        Arrays.asList(pred("namespace", Arrays.asList(s("ambient"), string(tenant), string(namespace))))
                )
        );
        authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s(namespace), string(tenant), string(namespace), s("create_topic"))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), s("topic"), string(tenant), string(namespace), var(2), s("produce")),
                Arrays.asList(pred("topic", Arrays.asList(s("ambient"), string(tenant), string(namespace), var(2))))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), s("topic"), string(tenant), string(namespace), var(2), s("consume")),
                Arrays.asList(pred("topic", Arrays.asList(s("ambient"), string(tenant), string(namespace), var(2))))));
        Biscuit biscuit = Biscuit.make(rng, root, symbols, authority_builder.build()).get();

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));
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
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.CREATE_TOPIC, null));
        assertTrue(authorizationProvider.canConsumeAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, null, null).get());
        assertTrue(authorizationProvider.canConsumeAsync(TopicName.get(tenant + "/" + namespace + "/" + "test123"), authedBiscuit, null, null).get());
        assertTrue(authorizationProvider.canProduceAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, null).get());
        assertTrue(authorizationProvider.canProduceAsync(TopicName.get(tenant + "/" + namespace + "/" + "test123"), authedBiscuit, null).get());
    }

    @Test
    public void testNamespaceOwner() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_fact(fact("revocation_id", Arrays.asList(date(Date.from(Instant.now())))));
        authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s("admin"))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("create_topic")),
                Arrays.asList(pred("namespace", Arrays.asList(s("authority"), var(0), var(1))))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("get_topic")),
                Arrays.asList(pred("namespace", Arrays.asList(s("authority"), var(0), var(1))))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("get_topics")),
                Arrays.asList(pred("namespace", Arrays.asList(s("authority"), var(0), var(1))))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("delete_topic")),
                Arrays.asList(pred("namespace", Arrays.asList(s("authority"), var(0), var(1))))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("add_bundle")),
                Arrays.asList(pred("namespace", Arrays.asList(s("authority"), var(0), var(1))))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("delete_bundle")),
                Arrays.asList(pred("namespace", Arrays.asList(s("authority"), var(0), var(1))))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("get_bundle")),
                Arrays.asList(pred("namespace", Arrays.asList(s("authority"), var(0), var(1))))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("clear_backlog")),
                Arrays.asList(pred("namespace", Arrays.asList(s("authority"), var(0), var(1))))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("unsubscribe")),
                Arrays.asList(pred("namespace", Arrays.asList(s("authority"), var(0), var(1))))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("produce")),
                Arrays.asList(pred("topic", Arrays.asList(s("authority"),  var(0), var(1), var(2))))));
        authority_builder.add_rule(rule("right",
                Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("consume")),
                Arrays.asList(pred("topic", Arrays.asList(s("authority"), var(0), var(1), var(2))))));;
        Biscuit rootBiscuit = Biscuit.make(rng, root, symbols, authority_builder.build()).get();

        Block block = rootBiscuit.create_block();
        block.add_caveat(caveat(rule("right",
                Arrays.asList(s("ambient"), s("namespace"), string(tenant), string(namespace)),
                Arrays.asList(pred("namespace", Arrays.asList(s("ambient"), string(tenant), string(namespace))))
        )));

        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block.build()).get();
        LOGGER.debug(biscuit.print());
        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));
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
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.CREATE_TOPIC, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.GET_TOPIC, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.GET_TOPICS, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.DELETE_TOPIC, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.ADD_BUNDLE, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.DELETE_BUNDLE, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.GET_BUNDLE, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.CLEAR_BACKLOG, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.UNSUBSCRIBE, null));
        assertTrue(authorizationProvider.canConsumeAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, null, null).get());
        assertTrue(authorizationProvider.canConsumeAsync(TopicName.get(tenant + "/" + namespace + "/" + "test123"), authedBiscuit, null, null).get());
        assertTrue(authorizationProvider.canProduceAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, null).get());
        assertTrue(authorizationProvider.canProduceAsync(TopicName.get(tenant + "/" + namespace + "/" + "test123"), authedBiscuit, null).get());
    }

    @Test
    public void testNamespaceOwnerWithPolicies() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_fact(fact("revocation_id", Arrays.asList(date(Date.from(Instant.now())))));
        authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s("admin"))));
        authority_builder.add_rule(constrained_rule("right",
                Arrays.asList(s("authority"), s("namespace"), var(0), var(1), var(2)),
                Arrays.asList(pred("ns_operation", Arrays.asList(s("authority"), s("namespace"), var(0), var(1), var(2)))),
                Arrays.asList(new com.clevercloud.biscuit.token.builder.constraints.SymbolConstraint.InSet(2, new HashSet<>(Arrays.asList(
                        "create_topic",
                        "get_topic",
                        "get_topics",
                        "delete_topic",
                        "add_bundle",
                        "delete_bundle",
                        "get_bundle",
                        "get_permission",
                        "grant_permission",
                        "revoke_permission",
                        "clear_backlog",
                        "unsubscribe",
                        "policy_all_read"
                ))))
        ));
        authority_builder.add_rule(constrained_rule("right",
                Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), var(3)),
                Arrays.asList(pred("topic_operation", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), var(3)))),
                Arrays.asList(new com.clevercloud.biscuit.token.builder.constraints.SymbolConstraint.InSet(3, new HashSet<>(Arrays.asList(
                        "lookup",
                        "consume",
                        "produce"
                ))))
        ));
        Biscuit rootBiscuit = Biscuit.make(rng, root, symbols, authority_builder.build()).get();

        Block block = rootBiscuit.create_block();
        block.add_caveat(
                new Caveat(Arrays.asList(
                        constrained_rule("limited_right",
                                Arrays.asList(s("namespace"), string(tenant), string(namespace), var(2)),
                                Arrays.asList(pred("ns_operation", Arrays.asList(s("namespace"), string(tenant), string(namespace), var(2)))),
                                Arrays.asList(new com.clevercloud.biscuit.token.builder.constraints.SymbolConstraint.InSet(2, new HashSet<>(Arrays.asList(
                                        "create_topic",
                                        "get_topic",
                                        "get_topics",
                                        "delete_topic",
                                        "add_bundle",
                                        "delete_bundle",
                                        "get_bundle",
                                        "get_permission",
                                        "grant_permission",
                                        "revoke_permission",
                                        "clear_backlog",
                                        "unsubscribe",
                                        "policy_all_read"
                                ))))
                        ),
                        constrained_rule("limited_right",
                                Arrays.asList(s("topic"), string(tenant), string(namespace), var(2), var(3)),
                                Arrays.asList(pred("topic_operation", Arrays.asList(s("topic"), string(tenant), string(namespace), var(2), var(3)))),
                                Arrays.asList(new com.clevercloud.biscuit.token.builder.constraints.SymbolConstraint.InSet(3, new HashSet<>(Arrays.asList(
                                        "lookup",
                                        "consume",
                                        "produce"
                                ))))
                        )
                ))
        );

        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block.build()).get();
        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));
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
        LOGGER.debug(biscuit.print());
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.CREATE_TOPIC, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.GET_TOPIC, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.GET_TOPICS, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.DELETE_TOPIC, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.ADD_BUNDLE, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.DELETE_BUNDLE, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.GET_BUNDLE, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.CLEAR_BACKLOG, null));
        assertTrue(authorizationProvider.allowNamespaceOperation(NamespaceName.get(tenant + "/" + namespace), null, authedBiscuit, NamespaceOperation.UNSUBSCRIBE, null));
        assertTrue(authorizationProvider.allowNamespacePolicyOperation(NamespaceName.get(tenant + "/" + namespace), PolicyName.ALL, PolicyOperation.READ, null, authedBiscuit, null));
        AuthenticationDataSource authData = new AuthenticationDataSource() {
            @Override
            public String getSubscription() {
                return null;
            }
        };
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + "test"), null, authedBiscuit, TopicOperation.CONSUME, authData));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + "test"), null, authedBiscuit, TopicOperation.PRODUCE, null));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + "test123"), null, authedBiscuit, TopicOperation.CONSUME, authData));
        assertTrue(authorizationProvider.allowTopicOperation(TopicName.get(tenant + "/" + namespace + "/" + "test123"), null, authedBiscuit, TopicOperation.PRODUCE, null));
    }

    @Test
    public void testBuild() {
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

        System.out.println(rootBiscuit.print());

        assertNotNull(rootBiscuit);
    }

    @Test
    public void testSuperUser() throws IOException, AuthenticationException, ExecutionException, InterruptedException {
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
        CompletableFuture<Boolean> authorizedFuture = authorizationProvider.isSuperUser(authedBiscuit, conf);
        assertTrue(authorizedFuture.get());
    }
}
