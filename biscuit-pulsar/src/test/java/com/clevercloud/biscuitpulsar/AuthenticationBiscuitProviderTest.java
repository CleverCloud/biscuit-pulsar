package com.clevercloud.biscuitpulsar;

import org.junit.Test;
import static org.junit.Assert.*;

public class AuthenticationBiscuitProviderTest {
  @Test
  public void testGetAuthMethodName() {
    AuthenticationBiscuitProvider authenticationPlugin = new AuthenticationBiscuitProvider();
    System.out.println(authenticationPlugin.getAuthMethodName());
    assertEquals("biscuit", authenticationPlugin.getAuthMethodName());
  }
}
