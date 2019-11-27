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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BiscuitAuthenticationPlugin implements AuthenticationProvider {
  private static final Logger LOGGER = LoggerFactory.getLogger(BiscuitAuthenticationPlugin.class);
  public static final String BISCUIT_SEALING_KEY = "biscuit-pulsar-key";
  private PublicKey rootKey;

  public void initialize(ServiceConfiguration serviceConfiguration) throws IOException {
    LOGGER.info("Initialize Apache Pulsar Biscuit authentication plugin");
    String key = (String) serviceConfiguration.getProperty("biscuitRootKey");
    LOGGER.info("got biscuit root key: {}", key);
    try {
      rootKey = new PublicKey(hexStringToByteArray(key));
    } catch (Exception e) {
      LOGGER.error("could not decode Biscuit root public key: {}", e);
      throw new IOException();
    }
  }

  public String getAuthMethodName() {
    return "biscuit";
  }

  public String authenticate(AuthenticationDataSource authenticationDataSource) throws AuthenticationException {
    LOGGER.info("Authentication data {}", authenticationDataSource);
    LOGGER.info("Authentication getCommandData {}", authenticationDataSource.getCommandData());
    LOGGER.info("Authentication getHttpAuthType {}", authenticationDataSource.getHttpAuthType());
    LOGGER.info("Authentication getPeerAddress {}", authenticationDataSource.getPeerAddress());

    List<String> decodedBytes = null;

    if (authenticationDataSource.getCommandData() == null) {
      String auth = authenticationDataSource.getHttpHeader("Authorization");

      if(auth == null) {
        throw new AuthenticationException("missing Authorization header");
      }
      LOGGER.info("Authorization HTTP header: {}", auth);
      if(auth.startsWith("Bearer ")) {
        decodedBytes = Arrays.asList(new String(auth.substring("Bearer ".length())).split(":"));
      } else if(auth.startsWith("Basic ")) {
        try {
          decodedBytes = Arrays.asList(URLDecoder.decode(new String(Base64.getUrlDecoder().decode(auth.substring("Basic ".length()))), StandardCharsets.UTF_8.toString()).split(":"));
        } catch (UnsupportedEncodingException e) {
          throw new AuthenticationException("cannot decode Authorization header");
        }

      } else {
        throw new AuthenticationException("unrecognized Authorization header");
      }
    } else {
      decodedBytes = Arrays.asList(authenticationDataSource.getCommandData().split(":"));
    }

    if(!decodedBytes.get(0).equals("biscuit")) {
      LOGGER.error("invalid token prefix(must be 'biscuit'): {}", decodedBytes.get(0));
      throw new AuthenticationException("invalid token prefix(must be 'biscuit')");
    }

    LOGGER.info("Authentication Authorization|| {}", decodedBytes);

    Either<Error, Biscuit> deser = Biscuit.from_bytes(Base64.getUrlDecoder().decode(decodedBytes.get(1)));

    if(deser.isLeft()) {
        throw new AuthenticationException("could not deserialize token");
    } else {
      Biscuit biscuit = deser.get();
      LOGGER.info("deserialized token");

      if(biscuit.check_root_key(rootKey).isLeft()) {
        throw new AuthenticationException("this token was not generated with the expected root key");
      }
      LOGGER.info("checked root key");

      byte[] sealed = biscuit.seal(BISCUIT_SEALING_KEY.getBytes()).get();
      LOGGER.info("token deserialized and sealed");
      return "biscuit:" + Base64.getEncoder().encodeToString(sealed);
    }
  }

  public void close() throws IOException {

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
