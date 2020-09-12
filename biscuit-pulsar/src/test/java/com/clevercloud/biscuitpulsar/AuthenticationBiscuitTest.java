package com.clevercloud.biscuitpulsar;

import org.junit.Test;
import static org.junit.Assert.*;
import org.apache.pulsar.client.api.AuthenticationDataProvider;

import org.apache.commons.io.FileUtils;
import org.apache.pulsar.client.api.Authentication;
import org.apache.pulsar.client.api.AuthenticationDataProvider;
import org.apache.pulsar.client.impl.PulsarClientImpl;
import org.apache.pulsar.client.impl.conf.ClientConfigurationData;

import java.util.Collections;

public class AuthenticationBiscuitTest {
  @Test
  public void testAuthBiscuitClientConfig() throws Exception {
    ClientConfigurationData clientConfig = new ClientConfigurationData();
    clientConfig.setServiceUrl("pulsar://service-url");
    clientConfig.setAuthPluginClassName(AuthenticationBiscuit.class.getName());
    clientConfig.setAuthParams("biscuit-xyz");

    PulsarClientImpl pulsarClient = new PulsarClientImpl(clientConfig);

    Authentication authBiscuit = pulsarClient.getConfiguration().getAuthentication();
    assertEquals(authBiscuit.getAuthMethodName(), "token");

    AuthenticationDataProvider authData = authBiscuit.getAuthData();
    assertTrue(authData.hasDataFromCommand());
    assertEquals(authData.getCommandData(), "biscuit-xyz");

    assertFalse(authData.hasDataForTls());
    assertNull(authData.getTlsCertificates());
    assertNull(authData.getTlsPrivateKey());

    assertTrue(authData.hasDataForHttp());
    assertEquals(authData.getHttpHeaders(),
      Collections.singletonMap("Authorization", "Bearer biscuit-xyz").entrySet());

    authBiscuit.close();
  }

  @Test
  public void testAuthBiscuitConfigNoPrefix() throws Exception {
    AuthenticationBiscuit authBiscuit = new AuthenticationBiscuit();
    authBiscuit.configure("my-test-biscuit-string");
    assertEquals(authBiscuit.getAuthMethodName(), "token");

    AuthenticationDataProvider authData = authBiscuit.getAuthData();
    assertTrue(authData.hasDataFromCommand());
    assertEquals(authData.getCommandData(), "my-test-biscuit-string");
    authBiscuit.close();
  }
}
