package com.clevercloud.biscuitpulsar.formatter;

import org.junit.Test;

import static com.clevercloud.biscuitpulsar.formatter.BiscuitFormatter.*;
import static org.junit.Assert.assertEquals;

public class BiscuitFormatterTest {
    @Test
    public void testNamespaceOperations() {
        assertEquals("[\"create_topic\",\"get_topic\",\"get_topics\",\"delete_topic\",\"get_bundle\",\"clear_backlog\",\"unsubscribe\"]", namespaceOperations);
    }

    @Test
    public void testPoliciesOperations() {
        assertEquals("[\"all_read\",\"anti_affinity_read\",\"auto_subscription_creation_read\",\"auto_subscription_creation_write\",\"auto_topic_creation_read\",\"auto_topic_creation_write\",\"backlog_read\",\"backlog_write\",\"compaction_read\",\"compaction_write\",\"deduplication_read\",\"deduplication_snapshot_read\",\"deduplication_snapshot_write\",\"deduplication_write\",\"delayed_delivery_read\",\"delayed_delivery_write\",\"encryption_read\",\"encryption_write\",\"inactive_topic_read\",\"inactive_topic_write\",\"max_consumers_read\",\"max_consumers_write\",\"max_producers_read\",\"max_producers_write\",\"max_subscriptions_read\",\"max_subscriptions_write\",\"max_topics_read\",\"max_topics_write\",\"max_unacked_read\",\"max_unacked_write\",\"offload_read\",\"partition_read\",\"partition_write\",\"persistence_read\",\"persistence_write\",\"rate_read\",\"rate_write\",\"replication_rate_read\",\"replication_read\",\"resourcegroup_read\",\"resourcegroup_write\",\"retention_read\",\"retention_write\",\"schema_compatibility_strategy_read\",\"schema_compatibility_strategy_write\",\"subscription_auth_mode_read\",\"subscription_auth_mode_write\",\"subscription_expiration_time_read\",\"subscription_expiration_time_write\",\"ttl_read\",\"ttl_write\"]", policiesOperations);
    }

    @Test
    public void testTopicOperations() {
        assertEquals("[\"lookup\",\"produce\",\"consume\",\"compact\",\"expire_messages\",\"offload\",\"peek_messages\",\"reset_cursor\",\"skip\",\"terminate\",\"get_bundle_range\",\"subscribe\",\"get_subscriptions\",\"unsubscribe\",\"get_stats\",\"get_metadata\",\"get_backlog_size\",\"set_replicated_subscription_status\"]", topicOperations);
    }
}