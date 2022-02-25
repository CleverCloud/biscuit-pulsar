package com.clevercloud.biscuitpulsar;

import com.google.common.base.Charsets;
import org.apache.pulsar.client.api.Authentication;
import org.apache.pulsar.client.api.AuthenticationDataProvider;
import org.apache.pulsar.client.api.EncodedAuthenticationParameterSupport;
import org.apache.pulsar.client.api.PulsarClientException;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Biscuit based authentication provider.
 */
public class AuthenticationBiscuit implements Authentication, EncodedAuthenticationParameterSupport {
    private Supplier<String> biscuitSupplier;

    public AuthenticationBiscuit() {
    }

    public AuthenticationBiscuit(String biscuit) {
        this(() -> biscuit);
    }

    public AuthenticationBiscuit(Supplier<String> biscuitSupplier) {
        this.biscuitSupplier = biscuitSupplier;
    }

    @Override
    public void close() throws IOException {
        // noop
    }

    @Override
    public String getAuthMethodName() {
        return "token";
    }

    @Override
    public AuthenticationDataProvider getAuthData() throws PulsarClientException {
        return new AuthenticationDataBiscuit(biscuitSupplier);
    }

    @Override
    public void configure(String encodedAuthParamString) {
        // Interpret the whole param string as the biscuit. If the string contains the notation `biscuit:xxxxx` then strip
        // the prefix
        if (encodedAuthParamString.startsWith("biscuit:")) {
            this.biscuitSupplier = () -> encodedAuthParamString.substring("biscuit:".length());
        } else if (encodedAuthParamString.startsWith("file:")) {
            // Read biscuit from a file
            URI filePath = URI.create(encodedAuthParamString);
            this.biscuitSupplier = () -> {
                try {
                    return Files.readString(Paths.get(filePath), Charsets.UTF_8).trim();
                } catch (IOException e) {
                    throw new RuntimeException("Failed to read biscuit from file", e);
                }
            };
        } else {
            this.biscuitSupplier = () -> encodedAuthParamString;
        }
    }

    @Override
    public void configure(Map<String, String> authParams) {
        // noop
    }

    @Override
    public void start() throws PulsarClientException {
        // noop
    }
}
