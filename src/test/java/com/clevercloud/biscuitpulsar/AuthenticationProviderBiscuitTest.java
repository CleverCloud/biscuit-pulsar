package com.clevercloud.biscuitpulsar;

import org.apache.pulsar.broker.authentication.AuthenticationState;
import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.UnverifiedBiscuit;
import org.biscuitsec.biscuit.token.builder.Block;
import org.hamcrest.core.StringStartsWith;
import org.junit.Test;

import javax.naming.AuthenticationException;
import javax.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.util.Arrays;

import static com.clevercloud.biscuitpulsar.BiscuitTestSupport.commandData;
import static org.biscuitsec.biscuit.token.builder.Utils.fact;
import static org.biscuitsec.biscuit.token.builder.Utils.s;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class AuthenticationProviderBiscuitTest {
    private static final String ROOT_KEY = "D283C7E436D89C544CC2B20C1028A7ADDC18FCED6386A6130465C17B996CD893";

    private final BiscuitTestSupport support = BiscuitTestSupport.withRoot(ROOT_KEY);

    /** A token signed by {@code signer} with the single right fact these tests were written with, seeded rng. */
    private Biscuit rightBiscuit(KeyPair signer) throws Exception {
        Block authority = new Block();
        authority.add_fact(fact("right", Arrays.asList(s("topic"), s("public"), s("default"), s("test"), s("produce"))));
        return Biscuit.make(new SecureRandom(new byte[]{0, 0, 0, 0}), signer, authority.build(support.symbols));
    }

    private static HttpServletRequest servletRequest() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        doReturn("127.0.0.1").when(request).getRemoteAddr();
        doReturn(0).when(request).getRemotePort();
        return request;
    }

    @Test
    public void testAuthSecretKeyPair() throws Exception {
        AuthenticationProviderBiscuit provider = support.authenticationProvider();

        String subject = provider.authenticate(commandData(rightBiscuit(support.root).serialize_b64url()));
        assertThat(subject, new StringStartsWith("biscuit:"));

        provider.close();
    }

    @Test
    public void testRevocation() throws Exception {
        AuthenticationProviderBiscuit provider = support.authenticationProvider();

        // its revocation id is listed in src/test/resources/revocation_list.hex.conf
        String revoked = UnverifiedBiscuit.from_b64url("EnYKDBgDIggKBggEEgIYDRIkCAASIDZFTlStxCxoVWTPpNT_K4i51-J9begIIm23SxZw_ECAGkADks3E29opT9JUJprQzl0a0unGMBsYmUUHTdBRiQ5JXdFr9TkPhOhJmiBFvehXlWNvLhVjCfm0JScJeZV-UCgKGvwBCpEBCilvcmdhXzVjMjg4MGM1LTBjOWUtNGI1YS1hY2FiLTA4NWVkMmY4Zjk1MAorcHVsc2FyXzQ5ZDdhYmU1LTEyOTAtNDAxNy04NjhlLTdkOWUxOGUzNzVmZgoFdG9waWMYAzIuChIKAggbEgwICRIDGIAIEgMYgQgKGAoCCBsSEgiCCBIDGIAIEgMYgQgSAwiCCBIkCAASIKx9Es26bZxaVm_LrNFkLL_8Mgr2tZPs9s5-aOsNYzK3GkD8qWru7MmK0LDe9KTYR2uUeLV0Q22jUEF2ZgKiSMuTcE6ivkc_bPH7W65prwVED5tS-Jdh18YFS_juIcMbhQUDIiIKIEYQvYZvVc98f-iejkWOGKm6Nia4El8Kohtim7X0FYgL").serialize_b64url();

        assertThrows("Biscuit has been revoked.", AuthenticationException.class, () -> provider.authenticate(commandData(revoked)));

        provider.close();
    }

    @Test
    public void testTokenFromHttpParams() throws Exception {
        AuthenticationProviderBiscuit provider = support.authenticationProvider();

        HttpServletRequest request = servletRequest();
        doReturn(rightBiscuit(support.root).serialize_b64url()).when(request).getParameter("token");
        doReturn(null).when(request).getHeader("Authorization");

        AuthenticationState authState = provider.newHttpAuthState(request);
        String subject = provider.authenticate(authState.getAuthDataSource());
        assertThat(subject, new StringStartsWith("biscuit:"));

        provider.close();
    }

    @Test
    public void testTokenFromHttpHeaders() throws Exception {
        AuthenticationProviderBiscuit provider = support.authenticationProvider();

        HttpServletRequest request = servletRequest();
        doReturn("Bearer " + rightBiscuit(support.root).serialize_b64url()).when(request).getHeader("Authorization");

        AuthenticationState authState = provider.newHttpAuthState(request);
        String subject = provider.authenticate(authState.getAuthDataSource());
        assertThat(subject, new StringStartsWith("biscuit:"));

        provider.close();
    }

    @Test
    public void testWrongKeyPair() throws Exception {
        AuthenticationProviderBiscuit provider = support.authenticationProvider();
        KeyPair wrongRoot = new KeyPair("D283C7E436D89C544CC2B20C1028A7ADDC18FCED6386A6130465C17B996CD894");

        String signedByWrongRoot = rightBiscuit(wrongRoot).serialize_b64url();
        assertThrows(AuthenticationException.class, () -> provider.authenticate(commandData(signedByWrongRoot)));

        provider.close();
    }
}
