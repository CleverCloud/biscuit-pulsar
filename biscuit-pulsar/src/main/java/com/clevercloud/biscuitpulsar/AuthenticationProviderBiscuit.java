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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthenticationProviderBiscuit implements AuthenticationProvider {
  private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationProviderBiscuit.class);

  final static String HTTP_HEADER_NAME = "Authorization";
  final static String HTTP_HEADER_VALUE_PREFIX = "Bearer ";

  final static String BISCUIT = "biscuit";

  public static final String BISCUIT_SEALING_KEY = "biscuit-pulsar-key";

  final static String CONF_BISCUIT_ROOT_KEY = "biscuitRootKey";

  private PublicKey rootKey;

  public void close() throws IOException {
    // noop
  }

  public void initialize(ServiceConfiguration serviceConfiguration) throws IOException {
    LOGGER.info("Initialize Apache Pulsar Biscuit authentication plugin");
    String key = (String) serviceConfiguration.getProperty(CONF_BISCUIT_ROOT_KEY);
    LOGGER.info("Got biscuit root public key: {}", key);
    try {
      rootKey = new PublicKey(hexStringToByteArray(key));
    } catch (Exception e) {
      LOGGER.error("Could not decode Biscuit root public key: {}", e);
      throw new IOException();
    }
  }

  public String getAuthMethodName() {
    return BISCUIT;
  }

  public String authenticate(AuthenticationDataSource authData) throws AuthenticationException {
    String biscuit = getBiscuit(authData);
    return parseBiscuit(biscuit);
  }

  public static String getBiscuit(AuthenticationDataSource authData) throws AuthenticationException {
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
      String biscuit = httpHeaderValue.substring(HTTP_HEADER_VALUE_PREFIX.length());
      return validateBiscuit(biscuit);
    } else {
      throw new AuthenticationException("No biscuit credentials passed");
    }
  }

  private static String validateBiscuit(final String biscuit) throws AuthenticationException {
    if (StringUtils.isNotBlank(biscuit)) {
      return biscuit;
    } else {
      throw new AuthenticationException("Blank biscuit found");
    }
  }

  private String parseBiscuit(final String biscuit) throws AuthenticationException {
    LOGGER.info("Biscuit to parse: {}", biscuit);

    Either<Error, Biscuit> deser = Biscuit.from_bytes(Base64.getUrlDecoder().decode(biscuit));

    if (deser.isLeft()) {
      throw new AuthenticationException("Could not deserialize biscuit");
    } else {
      Biscuit realBiscuit = deser.get();
      LOGGER.info("Deserialized biscuit");

      if (realBiscuit.check_root_key(rootKey).isLeft()) {
        throw new AuthenticationException("This biscuit was not generated with the expected root key");
      }
      LOGGER.info("Root key is valid");

      byte[] sealed = realBiscuit.seal(BISCUIT_SEALING_KEY.getBytes()).get();
      LOGGER.info("Biscuit deserialized and sealed");
      return "biscuit:" + Base64.getEncoder().encodeToString(sealed);
    }
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
