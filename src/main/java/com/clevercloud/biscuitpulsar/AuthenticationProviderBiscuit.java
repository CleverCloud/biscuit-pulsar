package com.clevercloud.biscuitpulsar;

import biscuit.format.schema.Schema;
import com.clevercloud.biscuit.crypto.PublicKey;
import com.clevercloud.biscuit.error.Error;
import com.clevercloud.biscuit.token.Biscuit;
import org.apache.commons.lang3.StringUtils;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authentication.AuthenticationProvider;
import org.apache.pulsar.broker.authentication.AuthenticationProviderToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Base64;

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

    public String getAuthMethodName() {
        return BISCUIT;
    }

    public String authenticate(AuthenticationDataSource authData) throws AuthenticationException {
        String bearer = getBearerValue(authData);

        if (isJWTSupported) {
            try {
                return parseBiscuit(bearer);
            } catch (AuthenticationException e) {
                log.debug("Biscuit decode failed, backing up to JWT");
                return jwtAuthenticator.authenticate(authData);
            }
        } else {
            return parseBiscuit(bearer);
        }
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
        log.debug("Biscuit to parse: {}", biscuitB64Url);
        try {
            Biscuit.from_b64url(biscuitB64Url, rootKey);
            log.debug("Deserialized biscuit");
            return "biscuit:" + biscuitB64Url;
        } catch (IllegalArgumentException | NoSuchAlgorithmException | SignatureException | InvalidKeyException | Error e) {
            throw new AuthenticationException(e.getMessage());
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
}
