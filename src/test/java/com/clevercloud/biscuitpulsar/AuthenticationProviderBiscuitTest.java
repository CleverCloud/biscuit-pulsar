package com.clevercloud.biscuitpulsar;

import com.clevercloud.biscuit.crypto.KeyPair;
import com.clevercloud.biscuit.datalog.SymbolTable;
import com.clevercloud.biscuit.token.Biscuit;
import com.clevercloud.biscuit.token.builder.Block;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.hamcrest.core.StringStartsWith;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;

import static com.clevercloud.biscuit.crypto.TokenSignature.hex;
import static com.clevercloud.biscuit.token.builder.Utils.fact;
import static com.clevercloud.biscuit.token.builder.Utils.s;
import static org.junit.Assert.assertThat;

public class AuthenticationProviderBiscuitTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationProviderBiscuitTest.class);

    @Test
    public void testAuthSecretKeyPair() throws Exception {
        KeyPair root = new KeyPair("3A8621F1847F19D6DAEAB5465CE8D3908B91C66FB9AF380D508FCF9253458907");

        LOGGER.info("ROOT KEY");
        LOGGER.info(root.toHex());

        LOGGER.info("ROOT PUBLICKEY");
        LOGGER.info(hex(root.public_key().key.getAbyte()));

        SymbolTable symbols = Biscuit.default_symbol_table();

        Block authority_builder = new Block(0, symbols);
        authority_builder.add_fact(fact("right", Arrays.asList(s("topic"), s("public"), s("default"), s("test"), s("produce"))));

        byte[] seed = {0, 0, 0, 0};
        SecureRandom rng = new SecureRandom(seed);
        Biscuit b = Biscuit.make(rng, root, Biscuit.default_symbol_table(), authority_builder.build());

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();

        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.getAbyte()));

        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);

        String biscuit = b.serialize_b64url();

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
