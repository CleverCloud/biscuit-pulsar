package com.clevercloud.biscuitpulsar;

import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.datalog.SymbolTable;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.builder.Block;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Properties;

import static com.clevercloud.biscuitpulsar.formatter.BiscuitFormatter.adminFact;
import static org.biscuitsec.biscuit.crypto.TokenSignature.hex;

/**
 * Shared fixtures for the provider tests: one root key pair per test, biscuit builders around it,
 * the broker configuration that trusts it, and the authenticated role string the authorization
 * provider expects. Tests then only state their checks and their assertions.
 */
final class BiscuitTestSupport {
    private static final Logger log = LoggerFactory.getLogger(BiscuitTestSupport.class);

    static final String TENANT = "tenantTest";
    static final String NAMESPACE = "namespaceTest";
    static final String TOPIC = "topicTest";
    /** {@code tenantTest/namespaceTest} */
    static final String NS = TENANT + "/" + NAMESPACE;
    /** {@code tenantTest/namespaceTest/topicTest} */
    static final String TOPIC_PATH = NS + "/" + TOPIC;

    final SecureRandom rng = new SecureRandom();
    final KeyPair root;
    final SymbolTable symbols = Biscuit.default_symbol_table();

    private BiscuitTestSupport(KeyPair root) {
        this.root = root;
    }

    /** A fresh random root key pair. */
    static BiscuitTestSupport randomRoot() {
        return new BiscuitTestSupport(new KeyPair(new SecureRandom()));
    }

    /** A fixed root key pair, for tokens serialized once and checked in. */
    static BiscuitTestSupport withRoot(String privateKeyHex) {
        return new BiscuitTestSupport(new KeyPair(privateKeyHex));
    }

    String publicKeyHex() {
        return hex(root.public_key().key.getAbyte());
    }

    /** A broker configuration whose biscuit root public key is this fixture's. */
    ServiceConfiguration conf() {
        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, publicKeyHex());
        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        return conf;
    }

    /** An authentication provider initialized against this fixture's root key. */
    AuthenticationProviderBiscuit authenticationProvider() throws Exception {
        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();
        provider.initialize(conf());
        return provider;
    }

    /** The cluster root token: {@code right("admin")} plus the given checks in the authority block. */
    Biscuit adminBiscuit(String... checks) throws Exception {
        Block authority = new Block();
        authority.add_fact(adminFact);
        for (String check : checks) {
            authority.add_check(check);
        }
        return Biscuit.make(rng, root, authority.build(symbols));
    }

    /** {@code biscuit} with one more block carrying the given checks. */
    Biscuit attenuate(Biscuit biscuit, String... checks) throws Exception {
        Block block = biscuit.create_block();
        for (String check : checks) {
            block.add_check(check);
        }
        return biscuit.attenuate(rng, root, block.build(symbols));
    }

    /**
     * Runs {@code biscuit} through the authentication provider and returns the role it yields
     * ({@code biscuit:<token>}). As a side effect this sets the static root key the authorization
     * provider reads, so call it before authorizing.
     */
    String authed(Biscuit biscuit) throws Exception {
        log.debug(biscuit.print());
        return authenticationProvider().authenticate(commandData(biscuit.serialize_b64url()));
    }

    /** Auth data as the binary protocol carries it. */
    static AuthenticationDataSource commandData(String token) {
        return new AuthenticationDataSource() {
            @Override
            public boolean hasDataFromCommand() {
                return true;
            }

            @Override
            public String getCommandData() {
                return token;
            }
        };
    }

    /** Auth data of a consumer bound to {@code subscription}. */
    static AuthenticationDataSource subscription(String subscription) {
        return new AuthenticationDataSource() {
            @Override
            public boolean hasSubscription() {
                return true;
            }

            @Override
            public String getSubscription() {
                return subscription;
            }
        };
    }
}
