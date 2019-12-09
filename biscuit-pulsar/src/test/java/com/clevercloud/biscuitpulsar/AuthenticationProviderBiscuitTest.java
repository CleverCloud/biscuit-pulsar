package com.clevercloud.biscuitpulsar;

import java.util.Properties;
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

public class AuthenticationProviderBiscuitTest {
  private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationProviderBiscuitTest.class);

  @Test
  public void testAuthSecretKeyPair() throws Exception {
    byte[] seed = {0, 0, 0, 0};
    SecureRandom rng = new SecureRandom(seed);
    KeyPair root = new KeyPair(rng);

    LOGGER.info("ROOT PUBLICKEY");
    LOGGER.info(hex(root.public_key().key.compress().toByteArray()));

    SymbolTable symbols = Biscuit.default_symbol_table();

    Block authority_builder = new Block(0, symbols);
    authority_builder.add_fact(fact("right", Arrays.asList(s("topic"), s("public"), s("default"), s("test"), s("produce"))));

    Biscuit b = Biscuit.make(rng, root, Biscuit.default_symbol_table(), authority_builder.build()).get();

    byte[] data = b.serialize().get();

    AuthenticationProviderBiscuit provider = new AuthenticationProviderBiscuit();

    Properties properties = new Properties();
    properties.setProperty(AuthenticationProviderBiscuit.CONF_BISCUIT_ROOT_KEY, hex(root.public_key().key.compress().toByteArray()));

    ServiceConfiguration conf = new ServiceConfiguration();
    conf.setProperties(properties);
    provider.initialize(conf);

    String biscuit = Base64.getUrlEncoder().encodeToString(data);

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
