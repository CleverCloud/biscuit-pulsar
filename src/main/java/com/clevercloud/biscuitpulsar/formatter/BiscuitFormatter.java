package com.clevercloud.biscuitpulsar.formatter;

import com.clevercloud.biscuitpulsar.operation.BiscuitNamespaceOperation;
import com.clevercloud.biscuitpulsar.operation.BiscuitPolicyOperation;
import com.clevercloud.biscuitpulsar.operation.BiscuitTopicOperation;
import org.apache.pulsar.common.naming.NamespaceName;
import org.apache.pulsar.common.naming.TopicName;
import org.apache.pulsar.common.policies.data.NamespaceOperation;
import org.apache.pulsar.common.policies.data.PolicyName;
import org.apache.pulsar.common.policies.data.PolicyOperation;
import org.apache.pulsar.common.policies.data.TopicOperation;

import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class BiscuitFormatter {
    /**
     * generates a string of biscuit symbols using the namespace operations
     * <p>
     * Example:
     * <code>
     * [#lookup,#produce,#consume,#compact, ...]
     * </code>
     */
    public static final String namespaceOperations =
            Arrays.stream(BiscuitNamespaceOperation.values())
                    .map(namespaceOperation -> namespaceOperation.toString().toLowerCase())
                    .collect(Collectors.joining(",#", "[#", "]"));
    /**
     * generates a string of biscuit symbols using the policies operations
     * <p>
     * Example:
     * <code>
     * [#all_read,#delayed_delivery_write,#rate_write,#subscription_auth_mode_read, ...]
     * </code>
     */
    public static final String policiesOperations =
            Arrays.stream(BiscuitPolicyOperation.values())
                    .map(policyOperation -> policyOperation.toString().toLowerCase())
                    .collect(Collectors.joining(",#", "[#", "]"));

    /**
     * generates a string of biscuit symbols using the topics operations
     * <p>
     * Example:
     * <code>
     * [#lookup,#produce,#consume,#compact, ...]
     * </code>
     */
    public static final String topicOperations =
            Arrays.stream(BiscuitTopicOperation.values())
                    .map(topicOperation -> topicOperation.toString().toLowerCase())
                    .collect(Collectors.joining(",#", "[#", "]"));

    public static String topicFactFragment(TopicName topic) {
        return Stream.of(topic.getTenant(), topic.getNamespacePortion(), topic.getLocalName())
                .collect(Collectors.joining("\",\"", "\"", "\""));
    }

    public static String namespaceFactFragment(NamespaceName namespace) {
        return Stream.of(namespace.getTenant(), namespace.getLocalName())
                .collect(Collectors.joining("\",\"", "\"", "\""));
    }

    public static String policyOperationFact(PolicyName policy, PolicyOperation operation) {
        return "#" + policy.toString().toLowerCase() + "_" + operation.toString().toLowerCase();
    }

    public static String topicOperationSymbol(TopicOperation operation) {
        return "#" + operation.toString().toLowerCase();
    }

    public
    static String namespaceOperationSymbol(NamespaceOperation operation) {
        return "#" + operation.toString().toLowerCase();
    }

    public static String namespacePolicyOperationFact(NamespaceName namespace, PolicyName policy, PolicyOperation operation) {
        return "namespace_operation(#ambient," + namespaceFactFragment(namespace) + "," + policyOperationFact(policy, operation) + ")";
    }

    public static String namespaceOperationFact(NamespaceName namespace, NamespaceOperation operation) {
        return "namespace_operation(#ambient," + namespaceFactFragment(namespace) + "," + namespaceOperationSymbol(operation) + ")";
    }

    public static String topicOperationFact(TopicName topic, TopicOperation operation) {
        return "topic_operation(#ambient," + topicFactFragment(topic) + "," + topicOperationSymbol(operation) + ")";
    }

    public static String topicPolicyOperationFact(TopicName topic, PolicyName policy, PolicyOperation operation) {
        return "topic_operation(#ambient," + topicFactFragment(topic) + "," + policyOperationFact(policy, operation) + ")";
    }

    public static String topicFact(TopicName topic) {
        return "topic(#ambient," + topicFactFragment(topic) + ")";
    }

    public static String namespaceFact(NamespaceName namespace) {
        return "namespace(#ambient," + namespaceFactFragment(namespace) + ")";
    }
}
