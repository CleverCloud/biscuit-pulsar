package com.clevercloud.biscuitpulsar;

import fr.jetoile.hadoopunit.HadoopUnitConfig;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.pulsar.client.api.*;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.concurrent.TimeUnit;
import static org.assertj.core.api.Assertions.assertThat;
import com.clevercloud.biscuit.crypto.KeyPair;
import com.clevercloud.biscuit.datalog.*;
import com.clevercloud.biscuit.error.FailedCaveat;
import com.clevercloud.biscuit.error.LogicError;
import com.clevercloud.biscuit.error.Error;
import com.clevercloud.biscuit.token.*;
import io.vavr.control.Either;

import java.security.SecureRandom;
import java.util.*;

import static com.clevercloud.biscuit.crypto.TokenSignature.hex;
import static com.clevercloud.biscuit.token.builder.Utils.*;

import com.clevercloud.biscuit.token.builder.Block;

public class BiscuitPulsarIntegrationTest {
  private static final Logger LOGGER = LoggerFactory.getLogger(BiscuitPulsarIntegrationTest.class);
  private static final String TOPIC_TEST = "public/default/test";
  private static final int NUM_OF_MESSAGES = 100;
  static private Configuration configuration;

  private static final String PULSAR_IP_CLIENT_KEY = "pulsar.client.ip";
  private static final String PULSAR_PORT_KEY = "pulsar.port";
  private static final String PULSAR_HTTP_PORT_KEY = "pulsar.http.port";

  @BeforeClass
  public static void setup() throws ConfigurationException {
    configuration = new PropertiesConfiguration(HadoopUnitConfig.DEFAULT_PROPS_FILE);
  }

  @Test
  public void biscuit() throws PulsarClientException {
    KeyPair root = new KeyPair("3A8621F1847F19D6DAEAB5465CE8D3908B91C66FB9AF380D508FCF9253458907");

    LOGGER.info("ROOT PUBLICKEY");
    LOGGER.info(hex(root.public_key().key.compress().toByteArray()));

    SymbolTable symbols = Biscuit.default_symbol_table();

    Block authority_builder = new Block(0, symbols);
    authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s("topic"), string("public"), string("default"), string("test"), s("produce"))));
    //authority_builder.add_fact(fact("right", Arrays.asList(s("authority"), s("admin"))));

    byte[] seed = {0, 0, 0, 0};
    SecureRandom rng = new SecureRandom(seed);
    Biscuit b = Biscuit.make(rng, root, Biscuit.default_symbol_table(), authority_builder.build()).get();
    String biscuit = b.serialize_b64().get();

    LOGGER.info("BISCUIT");
    LOGGER.info(biscuit);

    final PulsarClient client = PulsarClient.builder()
      .serviceUrl("pulsar://" + configuration.getString(PULSAR_IP_CLIENT_KEY) + ":" + configuration.getInt(PULSAR_PORT_KEY))
      //.serviceUrl("pulsar://localhost:6650")
      .authentication(AuthenticationBiscuit.class.getName(), biscuit)
      .build();

    final Producer<String> producer = client.newProducer(Schema.STRING)
      .topic(TOPIC_TEST)
      .enableBatching(false)
      .create();

    /*final Consumer<String> consumer = client.newConsumer(Schema.STRING)
      .topic(TOPIC_TEST)
      .subscriptionName("test-subs-1")
      .ackTimeout(10, TimeUnit.SECONDS)
      .subscriptionType(SubscriptionType.Exclusive)
      .subscribe();*/

    for (int i = 1; i <= NUM_OF_MESSAGES; ++i) {
      producer.send("Hello_" + i);
    }
    producer.close();
/*
    for (int i = 1; i <= NUM_OF_MESSAGES; ++i) {
      final Message<String> message = consumer.receive(1, TimeUnit.SECONDS);
      LOGGER.info("Message received : {}", message.getValue());
      assertThat(message.getValue()).isEqualTo("Hello_" + i);
    }

    consumer.close();*/
    client.close();
  }
}
