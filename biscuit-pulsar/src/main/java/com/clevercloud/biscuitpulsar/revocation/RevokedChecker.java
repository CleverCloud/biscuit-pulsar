package com.clevercloud.biscuitpulsar.revocation;

import com.clevercloud.biscuit.crypto.PublicKey;
import com.clevercloud.biscuit.token.Biscuit;
import com.clevercloud.biscuit.token.Verifier;
import io.vavr.control.Option;
import org.apache.pulsar.broker.ServiceConfiguration;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class RevokedChecker {
    public final static String CONF_BISCUIT_REVOCATION_URL = "biscuitRevocationAPIURL";

    private PublicKey rootKey;
    private String revokedIdsURL;
    private List<UUID> revokedList;

    public RevokedChecker(ServiceConfiguration serviceConfiguration, PublicKey rootKey) {
        this.rootKey = rootKey;
        this.revokedIdsURL = (String) serviceConfiguration.getProperty(CONF_BISCUIT_REVOCATION_URL);
    }

    public void startFetcher() {
    }

    public Boolean isRevoked(Biscuit b) {
        Verifier v = Verifier.make(b, Option.of(this.rootKey)).get();
        List<UUID> revoked = v.get_revocation_ids();
        List<UUID> intersect = revokedList.parallelStream()
                .filter(revoked::contains)
                .collect(Collectors.toList());

        return intersect.size() > 0;
    }

}
