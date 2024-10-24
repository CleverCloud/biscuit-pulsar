package com.clevercloud.biscuitpulsar;

import biscuit.format.schema.Schema;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.RevocationIdentifier;
import org.biscuitsec.biscuit.token.UnverifiedBiscuit;
import com.google.common.collect.Sets;
import org.apache.commons.lang3.StringUtils;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.*;
import org.apache.pulsar.common.api.AuthData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import javax.net.ssl.SSLSession;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.*;
import java.util.stream.Collectors;

public class AuthenticationProviderBiscuit implements AuthenticationProvider {
    private static final Logger log = LoggerFactory.getLogger(AuthenticationProviderBiscuit.class);

    final static String HTTP_HEADER_NAME = "Authorization";
    final static String HTTP_HEADER_VALUE_PREFIX = "Bearer ";

    final static String BISCUIT = "token";

    final static String CONF_BISCUIT_PUBLIC_ROOT_KEY = "biscuitPublicRootKey";
    final static String CONF_BISCUIT_SUPPORT_JWT = "biscuitSupportJWT";

    static PublicKey rootKey;

    private AuthenticationProviderToken jwtAuthenticator;
    private Boolean isJWTSupported;

    private Set<String> revokedIdentifiers;

    public void close() throws IOException {
        // noop
    }

    public void initialize(ServiceConfiguration serviceConfiguration) throws IOException {
        log.info("Initializing Pulsar Biscuit Authentication plugin...");
        log.info("With JWT authentication support?");
        isJWTSupported = Boolean.parseBoolean((String) serviceConfiguration.getProperty(CONF_BISCUIT_SUPPORT_JWT));
        if (isJWTSupported) {
            log.info("JWT authentication support ENABLED.");
            jwtAuthenticator = new AuthenticationProviderToken();
            jwtAuthenticator.initialize(serviceConfiguration);
            log.info("JWT authentication initialized.");
        } else {
            log.info("JWT authentication support DISABLED.");
        }

        loadRevocationList();

        log.info("Biscuit authentication configuration...");
        String key = (String) serviceConfiguration.getProperty(CONF_BISCUIT_PUBLIC_ROOT_KEY);
        log.debug("Got biscuit root public key: {}", key);
        try {
            rootKey = new PublicKey(Schema.PublicKey.Algorithm.Ed25519, hexStringToByteArray(key));
            log.info("Biscuit authentication initialized.");
        } catch (Exception ex) {
            log.error("Could not decode Biscuit root public key", ex);
            throw new IOException();
        }
    }

    /**
     * This load the revocation list from <code>/etc/biscuit/revocation_list.hex.conf</code>. If the file does not exists
     * it will fallback to the maven resources folder and load the file used for test <code>revocation_list.hex.conf</code>
     *
     * Please note that the Scanner usage if for performance issues.
     * @throws IOException
     */
    private void loadRevocationList() throws IOException {
        this.revokedIdentifiers = new HashSet<>();

        String defaultFilePath = "/etc/biscuit/revocation_list.hex.conf";
        File file = new File(defaultFilePath);

        if (file.exists() && !file.isDirectory() && file.canRead()) {
            log.info(String.format("Loading static revocation list from %s...", defaultFilePath));

            FileInputStream inputStream = null;
            Scanner sc = null;
            try {
                inputStream = new FileInputStream(file);
                sc = new Scanner(inputStream, StandardCharsets.UTF_8);
                while (sc.hasNextLine()) {
                    this.revokedIdentifiers.add(RevocationIdentifier.from_bytes(hexStringToByteArray(sc.nextLine())).serialize_b64url());
                }

                if (sc.ioException() != null) {
                    throw sc.ioException();
                }
            } finally {
                if (inputStream != null) {
                    inputStream.close();
                }
                if (sc != null) {
                    sc.close();
                }
            }
        } else {
            String fallbackFilePath = "revocation_list.hex.conf";
            log.info(String.format("Loading static revocation list from %s...", fallbackFilePath));
            InputStream revocationListStream = getClass().getClassLoader().getResourceAsStream(fallbackFilePath);
            assert revocationListStream != null;
            InputStreamReader streamReader = new InputStreamReader(revocationListStream, StandardCharsets.UTF_8);
            BufferedReader reader = new BufferedReader(streamReader);
            String line;
            while ((line = reader.readLine()) != null) {
                this.revokedIdentifiers.add(RevocationIdentifier.from_bytes(hexStringToByteArray(line)).serialize_b64url());
            }
            reader.close();
            streamReader.close();
            revocationListStream.close();
        }

        log.info(String.format("Loaded revocation list with %s item(s).", this.revokedIdentifiers.size()));
    }

    public String getAuthMethodName() {
        return BISCUIT;
    }

    public String authenticate(AuthenticationDataSource authData) throws AuthenticationException {
        String bearer = getBearerValue(authData);

        if (isJWTSupported) {
            try {
                return parseBiscuit(bearer);
            } catch (AuthenticationException e) {
                log.trace("Biscuit decode failed, backing up to JWT");
                return jwtAuthenticator.authenticate(authData);
            }
        } else {
            return parseBiscuit(bearer);
        }
    }

    @Override
    public AuthenticationState newAuthState(AuthData authData, SocketAddress remoteAddress, SSLSession sslSession)
            throws AuthenticationException {
        return new OneStageAuthenticationState(authData, remoteAddress, sslSession, this);
    }

    @Override
    public AuthenticationState newHttpAuthState(HttpServletRequest request) throws AuthenticationException {
        return new OneStageAuthenticationState(new HttpServletRequestWrapper(request), this);
    }

    public static String getBearerValue(AuthenticationDataSource authData) throws AuthenticationException {
        if (authData.hasDataFromCommand()) {
            // Authenticate Pulsar binary connection
            return authData.getCommandData();
        } else if (authData.hasDataFromHttp()) {
            // Authentication HTTP request. The format here should be compliant to RFC-6750
            // (https://tools.ietf.org/html/rfc6750#section-2.1). Eg: Authorization: Bearer xxxxxxxxxxxxx
            String httpHeaderValue = authData.getHttpHeader(HTTP_HEADER_NAME);
            if (httpHeaderValue == null || !httpHeaderValue.startsWith(HTTP_HEADER_VALUE_PREFIX)) {
                throw new AuthenticationException("Invalid HTTP Authorization header");
            }

            // Remove prefix
            String bearer = httpHeaderValue.substring(HTTP_HEADER_VALUE_PREFIX.length());
            return validateBearer(bearer);
        } else {
            throw new AuthenticationException("No biscuit credentials passed");
        }
    }

    private static String validateBearer(final String bearer) throws AuthenticationException {
        if (StringUtils.isNotBlank(bearer)) {
            return bearer;
        } else {
            throw new AuthenticationException("Blank Bearer found");
        }
    }

    private String parseBiscuit(final String biscuitB64Url) throws AuthenticationException {
        log.trace("Biscuit to parse: {}", biscuitB64Url);
        try {
            UnverifiedBiscuit biscuit = UnverifiedBiscuit.from_b64url(biscuitB64Url);
            Set<String> biscuitRevocationIdentifiers = biscuit.revocation_identifiers().stream().map(RevocationIdentifier::serialize_b64url).collect(Collectors.toSet());
            if (!Sets.intersection(revokedIdentifiers, biscuitRevocationIdentifiers).isEmpty()) {
                throw new AuthenticationException("Biscuit has been revoked.");
            }
            log.trace("Deserialized biscuit");
            return "biscuit:" + biscuitB64Url;
        } catch (IllegalArgumentException | Error e) {
            e.printStackTrace();
            throw new AuthenticationException(e.toString());
        }
    }

    // using that instead of Hex.decodeHex from commons-codec because there's an incompatibility with Pulsar's dependencies
    public static byte[] hexStringToByteArray(String hex) {
        int l = hex.length();
        byte[] data = new byte[l / 2];
        for (int i = 0; i < l; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static final class HttpServletRequestWrapper extends javax.servlet.http.HttpServletRequestWrapper {
        private final HttpServletRequest request;

        public HttpServletRequestWrapper(HttpServletRequest request) {
            super(request);
            this.request = request;
        }

        @Override
        public String getHeader(String name) {
            // The browser javascript WebSocket client couldn't add the auth param to the request header, use the
            // query param `token` to transport the auth token for the browser javascript WebSocket client.
            if (name.equals(HTTP_HEADER_NAME) && request.getHeader(HTTP_HEADER_NAME) == null) {
                String token = request.getParameter(BISCUIT);
                if (token != null) {
                    return !token.startsWith(HTTP_HEADER_VALUE_PREFIX) ? HTTP_HEADER_VALUE_PREFIX + token : token;
                }
            }
            return super.getHeader(name);
        }
    }
}
