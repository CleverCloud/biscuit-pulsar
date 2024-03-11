package com.clevercloud.biscuitpulsar.operation;

import org.apache.pulsar.common.policies.data.PolicyName;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public final class BiscuitPolicyOperation {

    private static final Set<PolicyName> POLICIES = new HashSet<>(Arrays.stream(PolicyName.values()).toList());

    private static final Set<PolicyName> POLICIES_WHITELISTED_WRITES = new HashSet<>(Arrays.asList(
            // PolicyName.ALL,
            // PolicyName.ANTI_AFFINITY,
            PolicyName.AUTO_SUBSCRIPTION_CREATION,
            PolicyName.AUTO_TOPIC_CREATION,
            PolicyName.BACKLOG,
            PolicyName.COMPACTION,
            PolicyName.DELAYED_DELIVERY,
            PolicyName.INACTIVE_TOPIC,
            PolicyName.DEDUPLICATION,
            // PolicyName.MAX_CONSUMERS,
            // PolicyName.MAX_PRODUCERS,
            PolicyName.DEDUPLICATION_SNAPSHOT,
            PolicyName.MAX_UNACKED,
            // PolicyName.MAX_SUBSCRIPTIONS,
            // PolicyName.OFFLOAD,
            PolicyName.PARTITION,
            PolicyName.PERSISTENCE,
            PolicyName.RATE,
            PolicyName.RETENTION,
            // PolicyName.REPLICATION,
            // PolicyName.REPLICATION_RATE,
            PolicyName.SCHEMA_COMPATIBILITY_STRATEGY,
            PolicyName.SUBSCRIPTION_AUTH_MODE,
            PolicyName.SUBSCRIPTION_EXPIRATION_TIME,
            PolicyName.ENCRYPTION,
            PolicyName.TTL
            // PolicyName.MAX_TOPICS,
            // PolicyName.RESOURCEGROUP,
            // PolicyName.ENTRY_FILTERS,
            // PolicyName.SHADOW_TOPIC,
            // PolicyName.DISPATCHER_PAUSE_ON_ACK_STATE_PERSISTENT,
    ));

    public static final Set<String> WHITELISTED_POLICIES_ACTIONS = POLICIES.stream()
            .flatMap(policy -> Arrays.stream(new String[]{String.format("%s_%s", policy.name().toUpperCase(), "READ"),
                    POLICIES_WHITELISTED_WRITES.contains(policy) ?
                            String.format("%s_%s", policy.name().toUpperCase(), "WRITE") : null}))
            .filter(Objects::nonNull)
            .collect(Collectors.toSet());
}