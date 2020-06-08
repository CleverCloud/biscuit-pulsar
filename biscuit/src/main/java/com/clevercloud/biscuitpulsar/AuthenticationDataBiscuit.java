package com.clevercloud.biscuitpulsar;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import org.apache.pulsar.client.api.AuthenticationDataProvider;

public class AuthenticationDataBiscuit implements AuthenticationDataProvider {
  public final static String HTTP_HEADER_NAME = "Authorization";

  private final Supplier<String> biscuitSupplier;

  public AuthenticationDataBiscuit(Supplier<String> biscuitSupplier) {
    this.biscuitSupplier = biscuitSupplier;
  }

  @Override
  public boolean hasDataForHttp() {
    return true;
  }

  @Override
  public Set<Map.Entry<String, String>> getHttpHeaders() {
    return Collections.singletonMap(HTTP_HEADER_NAME, "Bearer " + getBiscuit()).entrySet();
  }

  @Override
  public boolean hasDataFromCommand() {
    return true;
  }

  @Override
  public String getCommandData() {
    return getBiscuit();
  }

  private String getBiscuit() {
    try {
      return biscuitSupplier.get();
    } catch (Throwable t) {
      throw new RuntimeException("failed to get client biscuit", t);
    }
  }
}
