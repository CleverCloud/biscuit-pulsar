package com.clevercloud.biscuitpulsar;

import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.datalog.SymbolTable;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.UnverifiedBiscuit;
import org.biscuitsec.biscuit.token.builder.Block;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authentication.AuthenticationState;
import org.hamcrest.core.StringStartsWith;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import javax.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;

import static org.biscuitsec.biscuit.crypto.TokenSignature.hex;
import static org.biscuitsec.biscuit.token.builder.Utils.fact;
import static org.biscuitsec.biscuit.token.builder.Utils.s;
import static org.junit.Assert.assertThrows;
import static org.hamcrest.MatcherAssert.*;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class AuthenticationProviderBiscuitTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationProviderBiscuitTest.class);

    @Test
    public void testAuthSecretKeyPair() throws Exception {
        KeyPair root = new KeyPair("D283C7E436D89C544CC2B20C1028A7ADDC18FCED6386A6130465C17B996CD893");

        LOGGER.info("ROOT KEY");
        LOGGER.info(root.toHex());

        LOGGER.info("ROOT PUBLICKEY");
        LOGGER.info(hex(root.public_key().key.getAbyte()));

        SymbolTable symbols = Biscuit.default_symbol_table();

        Block authorityBuilder = new Block(0, symbols);
        authorityBuilder.add_fact(fact("right", Arrays.asList(s("topic"), s("public"), s("default"), s("test"), s("produce"))));

        byte[] seed = {0, 0, 0, 0};
        SecureRandom rng = new SecureRandom(seed);
        Biscuit b = Biscuit.make(rng, root, Biscuit.default_symbol_table(), authorityBuilder.build());

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


    @Test
    public void testRevocation() throws Exception {
        KeyPair root = new KeyPair("D283C7E436D89C544CC2B20C1028A7ADDC18FCED6386A6130465C17B996CD893");

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();

        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.getAbyte()));

        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);

        UnverifiedBiscuit unverifiedBiscuit = UnverifiedBiscuit.from_b64url("EnYKDBgDIggKBggEEgIYDRIkCAASIDZFTlStxCxoVWTPpNT_K4i51-J9begIIm23SxZw_ECAGkADks3E29opT9JUJprQzl0a0unGMBsYmUUHTdBRiQ5JXdFr9TkPhOhJmiBFvehXlWNvLhVjCfm0JScJeZV-UCgKGvwBCpEBCilvcmdhXzVjMjg4MGM1LTBjOWUtNGI1YS1hY2FiLTA4NWVkMmY4Zjk1MAorcHVsc2FyXzQ5ZDdhYmU1LTEyOTAtNDAxNy04NjhlLTdkOWUxOGUzNzVmZgoFdG9waWMYAzIuChIKAggbEgwICRIDGIAIEgMYgQgKGAoCCBsSEgiCCBIDGIAIEgMYgQgSAwiCCBIkCAASIKx9Es26bZxaVm_LrNFkLL_8Mgr2tZPs9s5-aOsNYzK3GkD8qWru7MmK0LDe9KTYR2uUeLV0Q22jUEF2ZgKiSMuTcE6ivkc_bPH7W65prwVED5tS-Jdh18YFS_juIcMbhQUDIiIKIEYQvYZvVc98f-iejkWOGKm6Nia4El8Kohtim7X0FYgL");
        String biscuit = unverifiedBiscuit.serialize_b64url();

        assertThrows("Biscuit has been revoked.", AuthenticationException.class, () -> {
            provider.authenticate(new AuthenticationDataSource() {
                @Override
                public boolean hasDataFromCommand() {
                    return true;
                }

                @Override
                public String getCommandData() {
                    return biscuit;
                }
            });
        });

        provider.close();
    }

    @Test
    public void testTokenFromHttpParams() throws Exception {
        KeyPair root = new KeyPair("D283C7E436D89C544CC2B20C1028A7ADDC18FCED6386A6130465C17B996CD893");

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();

        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.getAbyte()));

        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);

        SymbolTable symbols = Biscuit.default_symbol_table();

        Block authorityBuilder = new Block(0, symbols);
        authorityBuilder.add_fact(fact("right", Arrays.asList(s("topic"), s("public"), s("default"), s("test"), s("produce"))));

        byte[] seed = {0, 0, 0, 0};
        SecureRandom rng = new SecureRandom(seed);
        Biscuit b = Biscuit.make(rng, root, Biscuit.default_symbol_table(), authorityBuilder.build());

        HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        doReturn(b.serialize_b64url()).when(servletRequest).getParameter("token");
        doReturn(null).when(servletRequest).getHeader("Authorization");
        doReturn("127.0.0.1").when(servletRequest).getRemoteAddr();
        doReturn(0).when(servletRequest).getRemotePort();

        AuthenticationState authState = provider.newHttpAuthState(servletRequest);
        String subject = provider.authenticate(authState.getAuthDataSource());
        assertThat(subject, new StringStartsWith("biscuit:"));

        provider.close();
    }

    @Test
    public void testTokenFromHttpHeaders() throws Exception {
        KeyPair root = new KeyPair("D283C7E436D89C544CC2B20C1028A7ADDC18FCED6386A6130465C17B996CD893");

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();

        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.getAbyte()));

        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);

        SymbolTable symbols = Biscuit.default_symbol_table();

        Block authorityBuilder = new Block(0, symbols);
        authorityBuilder.add_fact(fact("right", Arrays.asList(s("topic"), s("public"), s("default"), s("test"), s("produce"))));

        byte[] seed = {0, 0, 0, 0};
        SecureRandom rng = new SecureRandom(seed);
        Biscuit b = Biscuit.make(rng, root, Biscuit.default_symbol_table(), authorityBuilder.build());
        HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        doReturn("Bearer " + b.serialize_b64url()).when(servletRequest).getHeader("Authorization");
        doReturn("127.0.0.1").when(servletRequest).getRemoteAddr();
        doReturn(0).when(servletRequest).getRemotePort();

        AuthenticationState authState = provider.newHttpAuthState(servletRequest);
        String subject = provider.authenticate(authState.getAuthDataSource());
        assertThat(subject, new StringStartsWith("biscuit:"));
        provider.close();
    }

    @Test
    public void testWrongKeyPair() throws Exception {
        KeyPair root = new KeyPair("D283C7E436D89C544CC2B20C1028A7ADDC18FCED6386A6130465C17B996CD893");
        KeyPair wrongRoot = new KeyPair("D283C7E436D89C544CC2B20C1028A7ADDC18FCED6386A6130465C17B996CD894");

        LOGGER.info("ROOT KEY");
        LOGGER.info(root.toHex());

        LOGGER.info("ROOT PUBLICKEY");
        LOGGER.info(hex(root.public_key().key.getAbyte()));

        SymbolTable symbols = Biscuit.default_symbol_table();

        Block authorityBuilder = new Block(0, symbols);
        authorityBuilder.add_fact(fact("right", Arrays.asList(s("topic"), s("public"), s("default"), s("test"), s("produce"))));

        byte[] seed = {0, 0, 0, 0};
        SecureRandom rng = new SecureRandom(seed);
        Biscuit b = Biscuit.make(rng, wrongRoot, Biscuit.default_symbol_table(), authorityBuilder.build());

        AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();

        Properties properties = new Properties();
        properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_PUBLIC_ROOT_KEY, hex(root.public_key().key.getAbyte()));

        ServiceConfiguration conf = new ServiceConfiguration();
        conf.setProperties(properties);
        provider.initialize(conf);

        String biscuit = b.serialize_b64url();

        // Assert that authenticate throws an exception
        assertThrows(AuthenticationException.class, () -> {
            provider.authenticate(new AuthenticationDataSource() {
                @Override
                public boolean hasDataFromCommand() {
                    return true;
                }

                @Override
                public String getCommandData() {
                    return biscuit;
                }
            });
        });

        provider.close();
    }
}
