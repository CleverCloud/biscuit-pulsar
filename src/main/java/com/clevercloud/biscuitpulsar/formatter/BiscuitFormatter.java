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

public final class BiscuitFormatter {
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
                    .collect(Collectors.joining("\",\"", "[\"", "\"]"));
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
                    .collect(Collectors.joining("\",\"", "[\"", "\"]"));

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
                    .collect(Collectors.joining("\",\"", "[\"", "\"]"));

    public static String namespacePolicyOperationFact(PolicyName policy, PolicyOperation operation) {
        return "namespace_operation(\"" + policy.toString().toLowerCase() + "_" + operation.toString().toLowerCase() + "\")";
    }

    public static String namespaceOperationFact(NamespaceOperation operation) {
        return "namespace_operation(\"" + operation.toString().toLowerCase() + "\")";
    }

    public static String topicOperationFragment(TopicOperation operation) {
        return "\"" + operation.name().toLowerCase() + "\"";
    }

    public static String topicOperationFact(TopicOperation operation) {
        return "topic_operation(" + topicOperationFragment(operation) + ")";
    }

    public static String topicPolicyOperationFact(PolicyName policy, PolicyOperation operation) {
        return "topic_operation(\"" + policy.toString().toLowerCase() + "_" + operation.toString().toLowerCase() + "\")";
    }

    public static String topicPolicyOperationFragment(PolicyName policy, PolicyOperation operation) {
        return "\"" + policy.name().toLowerCase() + "_" + operation.name().toLowerCase() + "\"";
    }

    public static String topicFragment(TopicName topic) {
        return Stream.of(topic.getTenant(), topic.getNamespacePortion(), TopicFormatter.sanitizeTopicName(topic))
                .collect(Collectors.joining("\",\"", "\"", "\""));
    }

    public static String topicVariableFragment(NamespaceName namespace) {
        return "\"" + namespace.getTenant() + "\",\"" + namespace.getLocalName() + "\", $topic";
    }

    public static String namespaceFragment(NamespaceName namespace) {
        return Stream.of(namespace.getTenant(), namespace.getLocalName())
                .collect(Collectors.joining("\",\"", "\"", "\""));
    }

    public static String namespaceOperationFragment(NamespaceOperation operation) {
        return "\"" + operation.name().toLowerCase() + "\"";
    }

    public static String namespacePolicyOperationFragment(PolicyName policy, PolicyOperation operation) {
        return "\"" + policy.name().toLowerCase() + "_" + operation.name().toLowerCase() + "\"";
    }

    public static String topicFact(TopicName topic) {
        return "topic(" + topicFragment(topic) + ")";
    }

    public static String topicVariableFact(NamespaceName namespace) {
        return "topic(" + topicVariableFragment(namespace) + ")";
    }

    public static String topicVariableFact(String tenant, String namespace) {
        return "topic(" + topicVariableFragment(NamespaceName.get(tenant + "/" + namespace)) + ")";
    }

    public static String namespaceFact(NamespaceName namespace) {
        return "namespace(\"" + namespace.getTenant() + "\",\"" + namespace.getLocalName() + "\")";
    }

    public static String namespaceFact(String tenant, String namespace) {
        return namespaceFact(NamespaceName.get(tenant, namespace));
    }

    public static String topicOperationCheck(TopicName topic, TopicOperation operation) {
        return "check if " + topicFact(topic) + "," + topicOperationFact(operation);
    }

    public static String adminFact = "right(\"admin\")";

    public static String adminCheck = "check if " + adminFact;
}
