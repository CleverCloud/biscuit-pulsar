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

public class BiscuitPulsarIntegrationTest {
  private static final Logger LOGGER = LoggerFactory.getLogger(BiscuitPulsarIntegrationTest.class);
  private static final String TOPIC = "hello";
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
  public void pulsarShouldStart() throws PulsarClientException {
    final PulsarClient client = PulsarClient.builder()
      .serviceUrl("pulsar://" + configuration.getString(PULSAR_IP_CLIENT_KEY) + ":" + configuration.getInt(PULSAR_PORT_KEY))
      .build();

    final Producer<String> producer = client.newProducer(Schema.STRING)
      .topic(TOPIC)
      .enableBatching(false)
      .create();

    final Consumer<String> consumer = client.newConsumer(Schema.STRING)
      .topic(TOPIC)
      .subscriptionName("test-subs-1")
      .ackTimeout(10, TimeUnit.SECONDS)
      .subscriptionType(SubscriptionType.Exclusive)
      .subscribe();

    for (int i = 1; i <= NUM_OF_MESSAGES; ++i) {
      producer.send("Hello_" + i);
    }
    producer.close();

    for (int i = 1; i <= NUM_OF_MESSAGES; ++i) {
      final Message<String> message = consumer.receive(1, TimeUnit.SECONDS);
      LOGGER.info("Message received : {}", message.getValue());
      assertThat(message.getValue()).isEqualTo("Hello_" + i);
    }

    consumer.close();
    client.close();
  }
}
