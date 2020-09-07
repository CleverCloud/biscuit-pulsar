package com.clevercloud.biscuitpulsar;

import com.clevercloud.biscuit.crypto.PublicKey;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authentication.AuthenticationProvider;
import com.clevercloud.biscuit.token.Biscuit;
import com.clevercloud.biscuit.error.Error;

import io.vavr.control.Either;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.apache.commons.lang3.StringUtils;

import org.apache.pulsar.broker.authentication.AuthenticationProviderToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthenticationProviderBiscuit implements AuthenticationProvider {
  private static final Logger log = LoggerFactory.getLogger(AuthenticationProviderBiscuit.class);

  final static String HTTP_HEADER_NAME = "Authorization";
  final static String HTTP_HEADER_VALUE_PREFIX = "Bearer ";

  final static String BISCUIT = "token";

  final static String CONF_BISCUIT_SEALING_KEY = "biscuitSealingKey";
  final static String CONF_BISCUIT_PUBLIC_ROOT_KEY = "biscuitPublicRootKey";
  final static String CONF_BISCUIT_SUPPORT_JWT = "biscuitSupportJWT";

  private PublicKey rootKey;
  static String SEALING_KEY;

  private AuthenticationProviderToken jwtAuthenticator;

  public void close() throws IOException {
    // noop
  }

  public void initialize(ServiceConfiguration serviceConfiguration) throws IOException {
    log.info("Initialize Pulsar Biscuit Authentication plugin...");

    log.info("With JWT authentication support?");
    Boolean supportJwt = Boolean.parseBoolean((String) serviceConfiguration.getProperty(CONF_BISCUIT_SUPPORT_JWT));
    if (supportJwt) {
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
    SEALING_KEY = (String) serviceConfiguration.getProperty(CONF_BISCUIT_SEALING_KEY);
    log.debug("Got biscuit sealing key: {}", SEALING_KEY);
    try {
      rootKey = new PublicKey(hexStringToByteArray(key));
      log.info("Biscuit authentication initialized.");
    } catch (Exception e) {
      log.error("Could not decode Biscuit root public key: {}", e);
      throw new IOException();
    }
  }

  public String getAuthMethodName() {
    return BISCUIT;
  }

  public String authenticate(AuthenticationDataSource authData) throws AuthenticationException {
    String bearer = getBearerValue(authData);

    if (isJWT(bearer)) {
      return jwtAuthenticator.authenticate(authData);
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

  private String parseBiscuit(final String biscuit) throws AuthenticationException {
    log.debug("Biscuit to parse: {}", biscuit);
    try {
      Either<Error, Biscuit> deser = Biscuit.from_b64(biscuit);

      if (deser.isLeft()) {
        throw new AuthenticationException("Could not deserialize biscuit");
      } else {
        Biscuit realBiscuit = deser.get();
        log.debug("Deserialized biscuit");

        if (realBiscuit.check_root_key(rootKey).isLeft()) {
          throw new AuthenticationException("This biscuit was not generated with the expected root key");
        }
        log.debug("Root key is valid");

        byte[] sealed = realBiscuit.seal(SEALING_KEY.getBytes()).get();
        log.debug("Biscuit deserialized and sealed");
        return "biscuit:" + Base64.getUrlEncoder().encodeToString(sealed);
      }
    } catch (IllegalArgumentException e) {
      throw new AuthenticationException(e.getMessage());
    }
  }

  public static boolean isJWT(String jwt) {
    // https://tools.ietf.org/html/rfc7519#section-7.2
    String[] splittedJWT = jwt.split("\\.");

    if (splittedJWT.length >= 2) {
      String encodedJOSEHeader = splittedJWT[0];
      return !encodedJOSEHeader.matches("\\S+");
    }
    return false;
  }

  // using that instead of Hex.decodeHex from commons-codec because there's an incompatibility with Pulsar's dependencies
  public static byte[] hexStringToByteArray(String hex) {
    int l = hex.length();
    byte[] data = new byte[l/2];
    for (int i = 0; i < l; i += 2) {
      data[i/2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
              + Character.digit(hex.charAt(i+1), 16));
    }
    return data;
  }
}
