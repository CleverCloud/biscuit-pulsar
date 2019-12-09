package com.clevercloud.biscuitpulsar;

import org.junit.Test;
import static org.junit.Assert.*;

public class AuthenticationProviderBiscuitTest {
  @Test
  public void testGetAuthMethodName() {
    AuthenticationProviderBiscuit authenticationPlugin = new AuthenticationProviderBiscuit();
    assertEquals("biscuit", authenticationPlugin.getAuthMethodName());
  }
}
