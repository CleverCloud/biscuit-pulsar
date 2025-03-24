package com.clevercloud.biscuitpulsar;

import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.datalog.SymbolTable;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.builder.Block;
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
import java.security.*;
import java.util.Properties;
import java.util.concurrent.ExecutionException;

import static org.biscuitsec.biscuit.crypto.TokenSignature.hex;
import static com.clevercloud.biscuitpulsar.formatter.BiscuitFormatter.*;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AuthorizationProviderBiscuitTest {
    static final Logger log = LoggerFactory.getLogger(AuthorizationProviderBiscuitTest.class);

    private String authedBiscuit(KeyPair root, Biscuit biscuit) throws IOException, AuthenticationException {
        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.getAbyte()));
        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);

        return provider.authenticate(new AuthenticationDataSource() {
            @Override
            public boolean hasDataFromCommand() {
                return true;
            }

            @Override
            public String getCommandData() {
                try {
                    return biscuit.serialize_b64url();
                } catch (Error.FormatError.SerializationError e) {
                    log.error("Can't deserialize biscuit due to: {}", e.getMessage());
                    return "";
                }
            }
        });
    }


    @Test
    public void testAccessOnlyToValidData() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";
        String topic = "topicTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        block0.add_check(topicOperationCheck(TopicName.get(tenant + "/" + namespace + "/" + topic), TopicOperation.PRODUCE));
        Biscuit biscuit = Biscuit.make(rng, root, block0.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        log.debug(biscuit.print());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/namespaceForbidden/" + topic), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get("tenantForbidden/" + namespace + "/" + topic), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/topicForbidden"), authedBiscuit, TopicOperation.PRODUCE, null).get());
    }
    

    @Test
    public void testProduceAndNotConsumeOnTopic() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";
        String topic = "topicTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        block0.add_check(topicOperationCheck(TopicName.get(tenant + "/" + namespace + "/" + topic), TopicOperation.PRODUCE));
        Biscuit biscuit = Biscuit.make(rng, root, block0.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        log.debug(biscuit.print());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.CONSUME, null).get());
    }

    @Test
    public void testProduceAndConsumeOnDifferentNamespacesTopics() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace1 = "ns1";
        String namespace2 = "ns2";
        String topic = "topicTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        String ns1Consume = topicOperation(TopicName.get(tenant + "/" + namespace1 + "/" + topic), TopicOperation.CONSUME);
        String ns2Produce = topicOperation(TopicName.get(tenant + "/" + namespace2 + "/" + topic), TopicOperation.PRODUCE);
        block0.add_check(String.format("check if %s or %s", ns1Consume, ns2Produce));
        Biscuit biscuit = Biscuit.make(rng, root, block0.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        log.debug(biscuit.print());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace1 + "/" + topic), authedBiscuit, TopicOperation.CONSUME, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace2 + "/" + topic), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace1 + "/" + topic), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace2 + "/" + topic), authedBiscuit, TopicOperation.CONSUME, null).get());
    }

    @Test
    public void testProduceAndNotConsumeAttenuatedOnTopic() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";
        String topic = "topicTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        Biscuit rootBiscuit = Biscuit.make(rng, root, block0.build(symbols));
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();

        String authedRootBiscuit = authedBiscuit(root, rootBiscuit);
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedRootBiscuit, TopicOperation.PRODUCE, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedRootBiscuit, TopicOperation.CONSUME, null).get());

        Block block1 = rootBiscuit.create_block();
        block1.add_check(topicOperationCheck(TopicName.get(tenant + "/" + namespace + "/" + topic), TopicOperation.PRODUCE));
        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block1.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);
        log.debug(biscuit.print());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.CONSUME, null).get());
    }

    @Test
    public void testConsumeAndNotProduceOnTopic() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";
        String topic = "topicTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        block0.add_check(topicOperationCheck(TopicName.get(tenant + "/" + namespace + "/" + topic), TopicOperation.CONSUME));
        Biscuit biscuit = Biscuit.make(rng, root, block0.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        log.debug(biscuit.print());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.CONSUME, null).get());
    }

    @Test
    public void testConsumerAndNotProduceAttenuatedOnTopic() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";
        String topic = "topicTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        Biscuit rootBiscuit = Biscuit.make(rng, root, block0.build(symbols));
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        
        String authedRootBiscuit = authedBiscuit(root, rootBiscuit);
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedRootBiscuit, TopicOperation.PRODUCE, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedRootBiscuit, TopicOperation.CONSUME, null).get());

        Block block1 = rootBiscuit.create_block();
        block1.add_check(topicOperationCheck(TopicName.get(tenant + "/" + namespace + "/" + topic), TopicOperation.CONSUME));
        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block1.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.CONSUME, null).get());
    }

    @Test
    public void testTopicCreation() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";
        
        //biscuit allowing "create topic" operation
        Block block0 = new Block();
        block0.add_fact(adminFact);
        block0.add_check("check if namespace_operation(\"create_topic\")");
        Biscuit rootBiscuit = Biscuit.make(rng, root, block0.build(symbols));

        String authedBiscuit = authedBiscuit(root, rootBiscuit);
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        log.debug(rootBiscuit.print());
        assertTrue(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.CREATE_TOPIC, null).get());
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.DELETE_TOPIC, null).get());
        assertTrue(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/namespace123"), authedBiscuit, NamespaceOperation.CREATE_TOPIC, null).get());
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/namespace123"), authedBiscuit, NamespaceOperation.DELETE_TOPIC, null).get());
        assertTrue(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get("tenant123/" + namespace), authedBiscuit, NamespaceOperation.CREATE_TOPIC, null).get());
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get("tenant123/" + namespace), authedBiscuit, NamespaceOperation.DELETE_TOPIC, null).get());

        //attenuate biscuit to limit access to a single tenant/namespace
        Block block1 = rootBiscuit.create_block();
        block1.add_check("check if " + namespaceFact(tenant, namespace));
        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block1.build(symbols));

        String attenuatedBiscuit = authedBiscuit(root, biscuit);
        log.debug(biscuit.print());
        assertTrue(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), attenuatedBiscuit, NamespaceOperation.CREATE_TOPIC, null).get());
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), attenuatedBiscuit, NamespaceOperation.DELETE_TOPIC, null).get());
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/namespace123"), attenuatedBiscuit, NamespaceOperation.CREATE_TOPIC, null).get());
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/namespace123"), attenuatedBiscuit, NamespaceOperation.DELETE_TOPIC, null).get());
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get("tenant123/" + namespace), attenuatedBiscuit, NamespaceOperation.CREATE_TOPIC, null).get());
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get("tenant123/" + namespace), attenuatedBiscuit, NamespaceOperation.DELETE_TOPIC, null).get());
    }

    @Test
    public void testReadWriteTopicInNamespace() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        block0.add_check("check if " + topicVariableFact(NamespaceName.get(tenant + "/" + namespace)) + ", topic_operation($operation), [\"produce\",\"consume\"].contains($operation)");
        Biscuit biscuit = Biscuit.make(rng, root, block0.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);
        log.debug(biscuit.print());
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.CONSUME, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test123"), authedBiscuit, TopicOperation.CONSUME, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test123"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/namespace123/test123"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get("tenant123/" + namespace + "/" + "test123"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        
        // Test any other operation which require more rights
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.DELETE_TOPIC, null).get());
    }

    @Test
    public void testTopicOperation() throws IOException, AuthenticationException, ExecutionException, InterruptedException, Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        Biscuit rootBiscuit = Biscuit.make(rng, root, block0.build(symbols));

        Block block1 = rootBiscuit.create_block();
        block1.add_check("check if " + topicVariableFact(tenant, namespace) + ", topic_operation($4)");
        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block1.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);
        log.debug(biscuit.print());
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.CONSUME, null).get());
        
        // Test any other operation which require more rights
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.DELETE_TOPIC, null).get());
    }

    @Test
    public void testLimitations() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        Biscuit rootBiscuit = Biscuit.make(rng, root, block0.build(symbols));

        Block block1 = rootBiscuit.create_block();
        block1.add_check("check if " + namespaceFact(tenant, namespace) + " or " + topicVariableFact(tenant, namespace));
        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block1.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();

        log.debug(biscuit.print());
        assertTrue(authorizationProvider.allowNamespacePolicyOperationAsync(NamespaceName.get(tenant + "/" + namespace), PolicyName.COMPACTION, PolicyOperation.WRITE, authedBiscuit, null).get());
        assertTrue(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.CREATE_TOPIC, null).get());
        assertTrue(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.GET_TOPIC, null).get());
        assertTrue(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.GET_TOPICS, null).get());
        assertTrue(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.DELETE_TOPIC, null).get());
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/random-ns"), authedBiscuit, NamespaceOperation.DELETE_TOPIC, null).get());
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get("random-tenant/" + namespace), authedBiscuit, NamespaceOperation.DELETE_TOPIC, null).get());
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.ADD_BUNDLE, null).get());
        assertFalse(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.DELETE_BUNDLE, null).get());
        assertTrue(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.GET_BUNDLE, null).get());
        assertTrue(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.CLEAR_BACKLOG, null).get());
        assertTrue(authorizationProvider.allowNamespaceOperationAsync(NamespaceName.get(tenant + "/" + namespace), authedBiscuit, NamespaceOperation.UNSUBSCRIBE, null).get());
        assertTrue(authorizationProvider.allowNamespacePolicyOperationAsync(NamespaceName.get(tenant + "/" + namespace), PolicyName.ALL, PolicyOperation.READ, authedBiscuit, null).get());
        assertTrue(authorizationProvider.allowNamespacePolicyOperationAsync(NamespaceName.get(tenant + "/" + namespace), PolicyName.TTL, PolicyOperation.READ, authedBiscuit, null).get());
        assertFalse(authorizationProvider.allowNamespacePolicyOperationAsync(NamespaceName.get(tenant + "/" + namespace), PolicyName.OFFLOAD, PolicyOperation.WRITE, authedBiscuit, null).get());
        assertTrue(authorizationProvider.allowNamespacePolicyOperationAsync(NamespaceName.get(tenant + "/" + namespace), PolicyName.SCHEMA_COMPATIBILITY_STRATEGY, PolicyOperation.WRITE, authedBiscuit, null).get());
        assertFalse(authorizationProvider.allowNamespacePolicyOperationAsync(NamespaceName.get(tenant + "/" + namespace), PolicyName.REPLICATION, PolicyOperation.WRITE, authedBiscuit, null).get());
        assertTrue(authorizationProvider.allowNamespacePolicyOperationAsync(NamespaceName.get(tenant + "/" + namespace), PolicyName.REPLICATION, PolicyOperation.READ, authedBiscuit, null).get());
        AuthenticationDataSource authData = new AuthenticationDataSource() {
            @Override
            public String getSubscription() {
                return null;
            }
        };

        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/random-ns/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get("random-tenant/random-ns/test"), authedBiscuit, TopicOperation.CONSUME, authData).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.CONSUME, authData).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test123"), authedBiscuit, TopicOperation.CONSUME, authData).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test123"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertTrue(authorizationProvider.allowTopicPolicyOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, PolicyName.ALL, PolicyOperation.READ, null).get());
        assertFalse(authorizationProvider.allowTopicPolicyOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, PolicyName.ALL, PolicyOperation.WRITE, null).get());

        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.getAbyte()));
        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        assertFalse(authorizationProvider.isSuperUser(authedBiscuit, null, conf).get());
    }

    @Test
    public void testSuperUser() throws IOException, AuthenticationException, ExecutionException, InterruptedException, Error.SymbolTableOverlap, Error.FormatError, Error.Language, Error.Parser {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        Block block0 = new Block();
        block0.add_fact(adminFact);
        Biscuit biscuit = Biscuit.make(rng, root, block0.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);
        log.debug(biscuit.print());

        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.getAbyte()));
        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        assertTrue(authorizationProvider.isSuperUser(authedBiscuit, null, conf).get());
        assertTrue(authorizationProvider.allowNamespacePolicyOperationAsync(NamespaceName.get("randomTenant/randomNamespace"), PolicyName.REPLICATION, PolicyOperation.WRITE, authedBiscuit, null).get());
    }

    @Test
    public void testNsLimitationsThenPrefixLimitation() throws IOException, AuthenticationException, ExecutionException, InterruptedException, Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        Biscuit rootBiscuit = Biscuit.make(rng, root, block0.build(symbols));

        // limit on ns tenant/namespace
        Block block1 = rootBiscuit.create_block();
        block1.add_check("check if " + namespaceFact(tenant, namespace) + " or " + topicVariableFact(tenant, namespace));
        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block1.build(symbols));

        // limit on tenant/namespace/PREFIX*
        String PREFIX = "INSTANCE_PREFIX_TO_DEFINE";
        Block block2 = biscuit.create_block();
        block2.add_check("check if " + topicVariableFact(tenant, namespace) + ", $topic.starts_with(\"" + PREFIX + "\")");
        biscuit = biscuit.attenuate(rng, root, block2.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);

        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();

        log.debug(biscuit.print());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/test"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + PREFIX), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + PREFIX + "-concat"), authedBiscuit, TopicOperation.PRODUCE, null).get());
    }

    @Test
    public void testLimitProduceOnTopicStartsWith() throws IOException, AuthenticationException, ExecutionException, InterruptedException, Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        // root token
        Block block0 = new Block();
        block0.add_fact(adminFact);
        Biscuit rootBiscuit = Biscuit.make(rng, root, block0.build(symbols));

        // limit on tenant/namespace/PREFIX*
        String PREFIX = "PREFIX";
        Block block2 = rootBiscuit.create_block();
        block2.add_check("check if " + topicVariableFact(tenant, namespace) + "," + topicOperationFact(TopicOperation.PRODUCE) + ", $topic.starts_with(\"" + PREFIX + "\")");
        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block2.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);

        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();

        log.debug(biscuit.print());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/test"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + PREFIX), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + PREFIX + "-concat"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/test"), authedBiscuit, TopicOperation.CONSUME, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + PREFIX), authedBiscuit, TopicOperation.CONSUME, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + PREFIX + "-concat"), authedBiscuit, TopicOperation.CONSUME, null).get());
    }

    @Test
    public void testConsumeOverrideLookup() throws IOException, AuthenticationException, ExecutionException, InterruptedException, Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        Biscuit rootBiscuit = Biscuit.make(rng, root, block0.build(symbols));

        Block block1 = rootBiscuit.create_block();
        block1.add_check("check if " + topicVariableFact(tenant, namespace) + "," + topicOperationFact(TopicOperation.CONSUME));
        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block1.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);

        log.debug(biscuit.print());
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.CONSUME, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/namespaceForbidden/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/namespaceForbidden/" + "test"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get("tenantForbidden/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get("tenantForbidden/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.PRODUCE, null).get());
    }

    @Test
    public void testProduceOverrideLookup() throws IOException, AuthenticationException, ExecutionException, InterruptedException, Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        Biscuit rootBiscuit = Biscuit.make(rng, root, block0.build(symbols));

        Block block1 = rootBiscuit.create_block();
        block1.add_check("check if " + topicVariableFact(tenant, namespace) + "," + topicOperationFact(TopicOperation.PRODUCE));
        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block1.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);

        log.debug(biscuit.print());
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/namespaceForbidden/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/namespaceForbidden/" + "test"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get("tenantForbidden/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get("tenantForbidden/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.PRODUCE, null).get());
    }

    @Test
    public void testLookupIsNotOverrodeByProduceOrConsume() throws IOException, AuthenticationException, ExecutionException, InterruptedException, Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        Biscuit rootBiscuit = Biscuit.make(rng, root, block0.build(symbols));

        Block block1 = rootBiscuit.create_block();
        block1.add_check("check if " + topicVariableFact(tenant, namespace) + "," + topicOperationFact(TopicOperation.LOOKUP));
        Biscuit biscuit = rootBiscuit.attenuate(rng, root, block1.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);

        log.debug(biscuit.print());
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/namespaceForbidden/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get("tenantForbidden/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.CONSUME, null).get());
    }

    @Test
    public void testLookupIsNotOverrodeByProduceOrConsumeWithBiscuitV3Compatibility() throws IOException, AuthenticationException, ExecutionException, InterruptedException, Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        KeyPair root = new KeyPair("005248AE3870664EFC914A287BD2DB70626316E2CD004FA138837E8430D9A5CF");

        String tenant = "tenantTest";
        String namespace = "namespaceTest";

        // biscuit generated with biscuit-java v3.0.1 of testLookupIsNotOverrodeByProduceOrConsume test
        Biscuit biscuit = Biscuit.from_b64url("EnYKDBgDIggKBggEEgIYDRIkCAASIOHcyKojONtsqsY1UjQQTQ3u3RT6b3lEYQ3qzBEemeaWGkDFlr56tGlo-Z1RloR1nScE13xMJWoOspcB5UP1FJ0Lt_0FCD4_3pccskLgDntQHAxc3ugF6Db8k4uUjs3EqJkLGs0BCmMKBXRvcGljCgp0ZW5hbnRUZXN0Cg1uYW1lc3BhY2VUZXN0Cg90b3BpY19vcGVyYXRpb24KBmxvb2t1cBgDMiQKIgoCCBsSEgiACBIDGIEIEgMYgggSAwiACBIICIMIEgMYhAgSJAgAEiAdRHtivWCRZ9IhUui2vkCFtCnCOQoGlgZ3QN1DAEc3BhpAI8SI62pQde-ZIjFX6qDV5rd-94_SRAk7EVGHmoY58ulf04dDX7jN4hIu28DE0Q0p3ebRxOwhuCCgabZl_NktBSIiCiAAUkiuOHBmTvyRSih70ttwYmMW4s0AT6E4g36EMNmlzw==", root.public_key());

        String authedBiscuit = authedBiscuit(root, biscuit);

        log.debug(biscuit.print());
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/namespaceForbidden/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get("tenantForbidden/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.LOOKUP, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + "test"), authedBiscuit, TopicOperation.CONSUME, null).get());
    }

    @Test
    public void testAuthorizeConsumptionOnSpecifiedTopic() throws IOException, AuthenticationException, ExecutionException, InterruptedException, Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";
        String topic = "topicTest";

        // create the cluster root biscuit
        Block block0 = new Block();
        block0.add_fact(adminFact);
        Biscuit rootBiscuit = Biscuit.make(rng, root, block0.build(symbols));

        // attenuate it to reduce its rights to one tenant/namespace only
        Block block1 = rootBiscuit.create_block();
        block1.add_check("check if " + namespaceFact(tenant, namespace) + " or " + topicVariableFact(tenant, namespace));
        Biscuit biscuit1 = rootBiscuit.attenuate(rng, root, block1.build(symbols));

        // attenuate it to reduce its rights to consume on tenant/namespace/topic only
        TopicName topicName = TopicName.get(String.format("%s/%s/%s", tenant, namespace, topic));
        Block block2 = biscuit1.create_block();
        block2.add_check("check if " + topicFact(topicName) + "," + topicOperationFact(TopicOperation.CONSUME));
        Biscuit biscuit2 = biscuit1.attenuate(rng, root, block2.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit2);

        log.debug(biscuit2.print());
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.CONSUME, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/namespaceForbidden/" + topic), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get("tenantForbidden/" + namespace + "/" + "topicForbidden"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get("tenantForbidden/" + namespace + "/" + topic), authedBiscuit, TopicOperation.PRODUCE, null).get());
    }

    @Test
    public void testAuthorizeConsumptionOnSpecifiedTopicPartioned() throws IOException, AuthenticationException, ExecutionException, InterruptedException, Error, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";
        String topic = "topicTest";

        // create the cluster root biscuit
        Block block0 = new Block();
        block0.add_fact(adminFact);
        Biscuit rootBiscuit = Biscuit.make(rng, root, block0.build(symbols));

        // attenuate it to reduce its rights to one tenant/namespace only
        Block block1 = rootBiscuit.create_block();
        block1.add_check("check if " + namespaceFact(tenant, namespace) + " or " + topicVariableFact(tenant, namespace));
        Biscuit biscuit1 = rootBiscuit.attenuate(rng, root, block1.build(symbols));

        // attenuate it to reduce its rights to consume on tenant/namespace/topic only
        TopicName topicName = TopicName.get(String.format("%s/%s/%s", tenant, namespace, topic));
        Block block2 = biscuit1.create_block();
        block2.add_check("check if " + topicFact(topicName) + "," + topicOperationFact(TopicOperation.CONSUME));
        Biscuit biscuit2 = biscuit1.attenuate(rng, root, block2.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit2);

        log.debug(biscuit2.print());
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();

        String topicWithPartitionTail = topic + "-partition-0";
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topicWithPartitionTail), authedBiscuit, TopicOperation.CONSUME, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/namespaceForbidden/" + topicWithPartitionTail), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get("tenantForbidden/" + namespace + "/" + "topicForbidden-partition-0"), authedBiscuit, TopicOperation.PRODUCE, null).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get("tenantForbidden/" + namespace + "/" +topicWithPartitionTail), authedBiscuit, TopicOperation.PRODUCE, null).get());
    }

    @Test
    public void testConsumeOnTopicWithAuthorizedSubscription() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";
        String topic = "topicTest";
        String subscription = "subNameTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        block0.add_check(topicOperationCheck(TopicName.get(tenant + "/" + namespace + "/" + topic), TopicOperation.CONSUME, subscription));
        Biscuit biscuit = Biscuit.make(rng, root, block0.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        log.debug(biscuit.print());
        AuthenticationDataSource authenticationDataSource = new AuthenticationDataSource() {
            @Override
            public boolean hasSubscription() {
                return true;
            }

            @Override
            public String getSubscription() {
                return subscription;
            }
        };
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.PRODUCE, authenticationDataSource).get());
        assertTrue(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.CONSUME, authenticationDataSource).get());
    }

    @Test
    public void testConsumeOnTopicWithUnauthorizedSubscription() throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";
        String topic = "topicTest";
        String subscription = "subNameTest";

        Block block0 = new Block();
        block0.add_fact(adminFact);
        block0.add_check(topicOperationCheck(TopicName.get(tenant + "/" + namespace + "/" + topic), TopicOperation.CONSUME, subscription));
        Biscuit biscuit = Biscuit.make(rng, root, block0.build(symbols));

        String authedBiscuit = authedBiscuit(root, biscuit);
        AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
        log.debug(biscuit.print());
        AuthenticationDataSource authenticationDataSource = new AuthenticationDataSource() {
            @Override
            public boolean hasSubscription() {
                return true;
            }

            @Override
            public String getSubscription() {
                return "wrongSubscriptionName";
            }
        };
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.PRODUCE, authenticationDataSource).get());
        assertFalse(authorizationProvider.allowTopicOperationAsync(TopicName.get(tenant + "/" + namespace + "/" + topic), authedBiscuit, TopicOperation.CONSUME, authenticationDataSource).get());
    }
}
