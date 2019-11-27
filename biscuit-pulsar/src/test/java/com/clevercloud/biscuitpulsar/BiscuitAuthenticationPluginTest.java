package com.clevercloud.biscuitpulsar;

import org.junit.Test;
import static org.junit.Assert.*;

public class BiscuitAuthenticationPluginTest {
    @Test
    public void testGetAuthMethodName() {
        BiscuitAuthenticationPlugin authenticationPlugin = new BiscuitAuthenticationPlugin();
        System.out.println(authenticationPlugin.getAuthMethodName());
        assertEquals("biscuit", authenticationPlugin.getAuthMethodName());
    }
}
