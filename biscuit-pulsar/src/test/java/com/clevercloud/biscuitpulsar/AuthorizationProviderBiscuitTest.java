package com.clevercloud.biscuitpulsar;

import com.clevercloud.biscuit.crypto.KeyPair;
import com.clevercloud.biscuit.datalog.SymbolTable;
import com.clevercloud.biscuit.error.Error;
import com.clevercloud.biscuit.token.Biscuit;
import com.clevercloud.biscuit.token.builder.Block;
import io.vavr.control.Either;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.common.naming.NamespaceName;
import org.apache.pulsar.common.naming.TopicName;
import org.apache.pulsar.common.policies.data.NamespaceOperation;
import org.hamcrest.core.StringStartsWith;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static com.clevercloud.biscuit.crypto.TokenSignature.hex;
import static com.clevercloud.biscuit.token.builder.Utils.*;
import static org.junit.Assert.assertThat;
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

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_rule(
                rule("right",
                        Arrays.asList(s("authority"), s("namespace"), string("tenant"), string("namespace"), s("create_topic")),
                        Arrays.asList(pred("namespace", Arrays.asList(s("ambient"), string("tenant"), string("namespace"))))
                )
        );
        authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s("namespace"), string("tenant"), string("namespace"), s("create_topic"))));
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
        Boolean authorized = authorizationProvider.allowNamespaceOperation(NamespaceName.get("clevercloud/logs"), null, authedBiscuit, NamespaceOperation.CREATE_TOPIC, null);
        assertTrue(authorized);
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
