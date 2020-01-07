package com.clevercloud.biscuitpulsar;

import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.apache.pulsar.common.naming.TopicName;
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

public class AuthorizationProviderBiscuitTest {
  private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationProviderBiscuitTest.class);

  @Test
  public void testAuthSecretKeyPair() throws Exception {
    KeyPair root = new KeyPair("3A8621F1847F19D6DAEAB5465CE8D3908B91C66FB9AF380D508FCF9253458907");

    LOGGER.info("ROOT PUBLICKEY");
    LOGGER.info(root.toHex());

    SymbolTable symbols = Biscuit.default_symbol_table();

    Block authority_builder = new Block(0, symbols);
    authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s("topic"), string("public"), string("default"), string("test"), s("produce"))));

    byte[] seed = {0, 0, 0, 0};
    SecureRandom rng = new SecureRandom(seed);
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

    AuthorizationProviderBiscuit authorizationProvider = new AuthorizationProviderBiscuit();
    AuthenticationDataSource authData = new AuthenticationDataSource() {
      @Override
      public boolean hasDataFromCommand() {
        return true;
      }

      @Override
      public String getCommandData() {
        return biscuit;
      }
    };
    CompletableFuture<Boolean> lookupAuthorizedFuture = authorizationProvider.canLookupAsync(TopicName.get("public/default/test"), subject, authData);
    assertTrue(lookupAuthorizedFuture.get());

    CompletableFuture<Boolean> produceAuthorizedFuture = authorizationProvider.canProduceAsync(TopicName.get("public/default/test"), subject, authData);
    assertTrue(produceAuthorizedFuture.get());
  }
}
