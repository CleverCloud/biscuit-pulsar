package com.clevercloud.biscuitpulsar.revocation;

import java.util.Properties;

import com.clevercloud.biscuitpulsar.AuthenticationProviderBiscuit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.security.SecureRandom;
import java.util.*;

import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.hamcrest.core.StringStartsWith;

import com.clevercloud.biscuit.crypto.KeyPair;
import com.clevercloud.biscuit.datalog.*;
import com.clevercloud.biscuit.token.*;
import static com.clevercloud.biscuit.crypto.TokenSignature.hex;
import static com.clevercloud.biscuit.token.builder.Utils.*;

import com.clevercloud.biscuit.token.builder.Block;

import org.junit.Test;
import static org.junit.Assert.*;

public class RevocationCheckTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(RevocationCheckTest.class);

    @Test
    public void testAuthSecretKeyPair() throws Exception {
        KeyPair root = new KeyPair("3A8621F1847F19D6DAEAB5465CE8D3908B91C66FB9AF380D508FCF9253458907");

        LOGGER.info("ROOT KEY");
        LOGGER.info(root.toHex());

        LOGGER.info("ROOT PUBLICKEY");
        LOGGER.info(hex(root.public_key().key.compress().toByteArray()));

        SymbolTable symbols = Biscuit.default_symbol_table();

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_fact(fact("right", Arrays.asList(s("topic"), s("public"), s("default"), s("test"), s("produce"))));

        byte[] seed = {0, 0, 0, 0};
        SecureRandom rng = new SecureRandom(seed);
        Biscuit b = Biscuit.make(rng, root, Biscuit.default_symbol_table(), authority_builder.build()).get();

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();

        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_SEALING_KEY, "test");
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_REVOCATION_ENABLED, "true");
        properties.setProperty(RevokedChecker.CONF_BISCUIT_REVOCATION_URL, "https://api.clever-cloud.com/v4/biscuit");
        properties.setProperty(RevokedChecker.CONF_BISCUIT_REVOCATION_FETCH_INTERVAL, "10");

        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);

        String biscuit = b.serialize_b64().get();

        String subject = provider.authenticate(new AuthenticationDataSource() {
            @Override
            public boolean hasDataFromCommand() {
                return true;
            }

            @Override
            public String getCommandData() {
                return biscuit;
            }
        });

        assertThat(subject, new StringStartsWith("biscuit:"));

        provider.close();
    }
}
