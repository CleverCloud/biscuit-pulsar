package com.clevercloud.biscuitpulsar.formatter;

import org.apache.pulsar.common.naming.TopicName;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class TopicFormatterTest {
    @Test
    public void testSanitizeTopicName() {
        TopicName topicNamePartitioned = TopicName.get("topic-partition-0");
        assertEquals("topic", TopicFormatter.sanitizeTopicName(topicNamePartitioned));
        TopicName topicName = TopicName.get("topic-partition-0");
        assertEquals("topic", TopicFormatter.sanitizeTopicName(topicName));

        TopicName semiQualifiedTopicNamePartitioned = TopicName.get("tenant/namespace/topic-partition-0");
        assertEquals("topic", TopicFormatter.sanitizeTopicName(semiQualifiedTopicNamePartitioned));
        TopicName semiQualifiedTopicName = TopicName.get("tenant/namespace/topic");
        assertEquals("topic", TopicFormatter.sanitizeTopicName(semiQualifiedTopicName));

        TopicName fullyQualifiedTopicNamePartitioned = TopicName.get("persistent://tenant/namespace/topic-partition-0");
        assertEquals("topic", TopicFormatter.sanitizeTopicName(fullyQualifiedTopicNamePartitioned));
        TopicName fullyQualifiedTopicName = TopicName.get("persistent://tenant/namespace/topic");
        assertEquals("topic", TopicFormatter.sanitizeTopicName(fullyQualifiedTopicName));
    }
}
