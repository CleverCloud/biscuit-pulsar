package com.clevercloud.biscuitpulsar.revocation;

import com.clevercloud.biscuit.crypto.PublicKey;
import com.clevercloud.biscuit.error.Error;
import com.clevercloud.biscuit.token.Biscuit;
import com.clevercloud.biscuit.token.Verifier;
import io.netty.util.concurrent.DefaultThreadFactory;
import io.vavr.control.Either;
import io.vavr.control.Option;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static io.vavr.API.Left;
import static io.vavr.API.Right;

public class RevokedChecker {
    private static final Logger log = LoggerFactory.getLogger(RevokedChecker.class);

    public final static String CONF_BISCUIT_REVOCATION_URL = "biscuitRevocationAPIURL";
    public final static String CONF_BISCUIT_REVOCATION_FETCH_INTERVAL = "biscuitRevocationFetchInterval";

    private PublicKey rootKey;
    private String revokedIdsURL;
    private int fetchInterval;
    private List<UUID> revokedList;

    private ScheduledExecutorService fetchRevokedExecutor;

    public RevokedChecker(ServiceConfiguration serviceConfiguration, PublicKey rootKey) {
        this.rootKey = rootKey;
        this.revokedIdsURL = (String) serviceConfiguration.getProperty(CONF_BISCUIT_REVOCATION_URL);
        this.fetchInterval = Integer.parseInt((String) serviceConfiguration.getProperty(CONF_BISCUIT_REVOCATION_FETCH_INTERVAL));

        this.fetchRevokedExecutor = Executors.newSingleThreadScheduledExecutor(new DefaultThreadFactory("revoked-fetcher"));
    }

    public Either<IOException, Void> startFetcher() {
        log.info("First fetch");

        Either<IOException, List<UUID>> firstFetch = fetch();

        if (firstFetch.isLeft()) {
            return Left(firstFetch.getLeft());
        }

        final int initialDelay = this.fetchInterval;
        final int interval = this.fetchInterval;
        log.info("Scheduling a thread to fetch revoked after [{}] seconds in background", interval);
        this.fetchRevokedExecutor.scheduleAtFixedRate(this::fetch, initialDelay, interval, TimeUnit.SECONDS);

        return Right(null);
    }

    private Either<IOException, List<UUID>> fetch() {
        Response response = ClientBuilder
                .newClient()
                .target(revokedIdsURL)
                .request(MediaType.APPLICATION_JSON)
                .get();

        if (response.getStatus() >= 200 && response.getStatus() <= 299) {
            List<UUID> newList = response.readEntity(new GenericType<List<UUID>>() {});
            log.debug(newList.toString());
            this.revokedList = newList;
            return Right(newList);
        } else {
            log.error("Can't fetch revocation list from URL: {}, HTTP STATUS: {}.", revokedIdsURL, response.getStatus());
            return Left(new IOException("Can't fetch revocation list from URL: " + revokedIdsURL + ", HTTP STATUS: " + response.getStatus()));
        }
    }

    public Boolean isRevoked(Biscuit b) throws IllegalArgumentException {
        Either<Error, Verifier> either = Verifier.make(b, Option.of(this.rootKey));

        return either.map(verifier -> {
            List<UUID> revoked = verifier.get_revocation_ids();
            List<UUID> intersect = revokedList.parallelStream()
                    .filter(revoked::contains)
                    .collect(Collectors.toList());

            return intersect.size() > 0;
        }).getOrElseThrow(error -> new IllegalArgumentException("Biscuit Verifier can't be created" + error.toString()));
    }
}
