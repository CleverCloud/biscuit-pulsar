package com.clevercloud.biscuitpulsar.formatter;

import org.apache.pulsar.common.naming.TopicName;

public class TopicFormatter {
    public static String sanitizeTopicName(TopicName topicName) {
        String localName = topicName.getLocalName();
        if (topicName.isPartitioned()) {
            return localName.substring(0, localName.lastIndexOf("-partition-"));
        } else {
            return localName;
        }
    }
}
