package com.clevercloud.biscuitpulsar;

import com.clevercloud.biscuit.datalog.RunLimits;
import com.clevercloud.biscuit.error.Error;
import com.clevercloud.biscuit.token.Authorizer;
import com.clevercloud.biscuit.token.Biscuit;
import io.vavr.control.Either;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authorization.AuthorizationProvider;
import org.apache.pulsar.broker.authorization.PulsarAuthorizationProvider;
import org.apache.pulsar.broker.resources.PulsarResources;
import org.apache.pulsar.common.naming.NamespaceName;
import org.apache.pulsar.common.naming.TopicName;
import org.apache.pulsar.common.policies.data.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;

import static com.clevercloud.biscuitpulsar.formatter.BiscuitFormatter.*;

public class AuthorizationProviderBiscuit implements AuthorizationProvider {
    private static final Logger log = LoggerFactory.getLogger(AuthorizationProviderBiscuit.class);

    final static String CONF_BISCUIT_RUNLIMITS_MAX_FACTS = "biscuitRunLimitsMaxFacts";
    final static String CONF_BISCUIT_RUNLIMITS_MAX_ITERATIONS = "biscuitRunLimitsMaxIterations";
    final static String CONF_BISCUIT_RUNLIMITS_MAX_TIME = "biscuitRunLimitsMaxTimeMillis";

    public ServiceConfiguration conf;
    public PulsarResources pulsarResources;
    private PulsarAuthorizationProvider defaultProvider;
    private RunLimits runLimits;

    public AuthorizationProviderBiscuit() {
        // TODO: we increase the timeout duration due to JVM warmup, need to find a fix
        runLimits = new RunLimits(1000, 100, Duration.ofMillis(20));
    }

    public AuthorizationProviderBiscuit(ServiceConfiguration conf, PulsarResources pulsarResources)
            throws IOException {
        initialize(conf, pulsarResources);
        runLimits = new RunLimits(
                Integer.parseInt((String) conf.getProperty(CONF_BISCUIT_RUNLIMITS_MAX_FACTS)),
                Integer.parseInt((String) conf.getProperty(CONF_BISCUIT_RUNLIMITS_MAX_ITERATIONS)),
                Duration.ofMillis(Integer.parseInt((String) conf.getProperty(CONF_BISCUIT_RUNLIMITS_MAX_TIME)))
        );
    }

    @Override
    public void initialize(ServiceConfiguration conf, PulsarResources pulsarResources) throws IOException {
        this.conf = conf;
        this.pulsarResources = pulsarResources;
        defaultProvider = new PulsarAuthorizationProvider(conf, pulsarResources);
    }

    private Either<Exception, Authorizer> authorizerFromBiscuitB64Url(String role) {
        try {
            Biscuit sealedBiscuit = Biscuit.from_b64url(role.substring("biscuit:".length()), AuthenticationProviderBiscuit.rootKey);
            Authorizer authorizer = sealedBiscuit.authorizer();
            return Either.right(authorizer);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | Error ex) {
            log.error("Failed to deserialize Biscuit from sealed [{}] due to [{}].", role, ex);
            return Either.left(ex);
        }
    }

    private CompletableFuture<Boolean> authorize(Callable<CompletableFuture<Boolean>> notBiscuitFallback, Boolean withSuperUserFallback,
                                                 String action, String role, AuthenticationDataSource authenticationData,
                                                 Set<String> facts, Set<String> rules, Set<String> checks) {
        if (!role.startsWith("biscuit:")) {
            try {
                return notBiscuitFallback.call();
            } catch (Exception ex) {
                log.error("Error during notBiscuitFallback call", ex);
                return CompletableFuture.failedFuture(ex);
            }
        }

        return authorizerFromBiscuitB64Url(role)
                .fold(CompletableFuture::failedFuture,
                        authorizer -> {
                            try {
                                authorizer.set_time();
                                authorizer.add_check(adminCheck);
                                for (String fact : facts) authorizer.add_fact(fact);
                                for (String rule : rules) authorizer.add_rule(rule);
                                for (String check : checks) authorizer.add_check(check);
                                authorizer.allow();
                                log.debug(authorizer.print_world());
                                authorizer.authorize(runLimits);
                            } catch (Error ex) {
                                log.debug("BiscuitAuthorization [{}] unauthorized role -> [{}]", action, role, ex);
                                if (withSuperUserFallback) {
                                    log.debug("Will fallback with isSuperUser check");
                                    return isSuperUser(role, authenticationData, this.conf);
                                } else {
                                    log.debug("No isSuperUSer fallback, returning unauthorized.");
                                    return CompletableFuture.completedFuture(false);
                                }
                            }
                            log.debug("BiscuitAuthorization [{}] authorized.", action);
                            return CompletableFuture.completedFuture(true);
                        });
    }

    @Override
    public CompletableFuture<Boolean> canProduceAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData) {
        return allowTopicOperationAsync(topicName, role, TopicOperation.PRODUCE, authenticationData);
    }

    @Override
    public CompletableFuture<Boolean> canConsumeAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData, String subscription) {
        return allowTopicOperationAsync(topicName, role, TopicOperation.CONSUME, authenticationData);
    }

    @Override
    public CompletableFuture<Boolean> canLookupAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData) {
        return allowTopicOperationAsync(topicName, role, TopicOperation.LOOKUP, authenticationData);
    }

    @Override
    public CompletableFuture<Boolean> allowFunctionOpsAsync(NamespaceName namespaceName, String role, AuthenticationDataSource authenticationData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowFunctionOpsAsync(namespaceName, role, authenticationData);
        }
        return isSuperUser(role, authenticationData, this.conf);
    }

    @Override
    public CompletableFuture<Boolean> allowSourceOpsAsync(NamespaceName namespaceName, String s, AuthenticationDataSource authenticationDataSource) {
        return null;
    }

    @Override
    public CompletableFuture<Boolean> allowSinkOpsAsync(NamespaceName namespaceName, String s, AuthenticationDataSource authenticationDataSource) {
        return null;
    }

    @Override
    public CompletableFuture<Boolean> isSuperUser(String role, AuthenticationDataSource authenticationData, ServiceConfiguration serviceConfiguration) {
        return authorize(() -> defaultProvider.isSuperUser(role, authenticationData, serviceConfiguration), false, "isSuperUser", role, authenticationData, Set.of(), Set.of(), Set.of());
    }

    @Override
    public CompletableFuture<Boolean> allowTenantOperationAsync(String tenantName, String role, TenantOperation operation, AuthenticationDataSource authData) {
        return isSuperUser(role, authData, this.conf);
    }

    @Override
    public CompletableFuture<Boolean> allowNamespaceOperationAsync(NamespaceName namespaceName, String role, NamespaceOperation operation, AuthenticationDataSource authData) {
        Set<String> facts = Set.of(
                namespaceFact(namespaceName),
                namespaceOperationFact(operation)
        );
        Set<String> rules = Set.of("right($tenant, $namespace, $operation) <- namespace($tenant, $namespace), namespace_operation($operation), " + namespaceOperations + ".contains($operation)");
        Set<String> checks = Set.of("check if right(" + namespaceFragment(namespaceName) + "," + namespaceOperationFragment(operation) + ")");
        return authorize(() -> defaultProvider.allowNamespaceOperationAsync(namespaceName, role, operation, authData), true, "allowNamespaceOperationAsync(" + operation + " -> " + namespaceName + ")", role, authData, facts, rules, checks);
    }

    @Override
    public CompletableFuture<Boolean> allowNamespacePolicyOperationAsync(NamespaceName namespaceName, PolicyName policy, PolicyOperation operation, String role, AuthenticationDataSource authData) {
        Set<String> facts = Set.of(
                namespaceFact(namespaceName),
                namespacePolicyOperationFact(policy, operation)
        );
        Set<String> rules = Set.of("right($tenant, $namespace, $operation) <- namespace($tenant, $namespace), namespace_operation($operation), " + policiesOperations + ".contains($operation)");
        Set<String> checks = Set.of("check if right(" + namespaceFragment(namespaceName) + "," + namespacePolicyOperationFragment(policy, operation) + ")");
        return authorize(() -> defaultProvider.allowNamespacePolicyOperationAsync(namespaceName, policy, operation, role, authData), true, "allowNamespacePolicyOperationAsync(" + policy + "." + operation + " -> " + namespaceName + ")", role, authData, facts, rules, checks);
    }

    @Override
    public CompletableFuture<Boolean> allowTopicOperationAsync(TopicName topicName, String role, TopicOperation operation, AuthenticationDataSource authData) {
        Set<String> facts = new HashSet<>(Set.of(
                topicFact(topicName),
                topicOperationFact(operation)
        ));
        if (operation.equals(TopicOperation.LOOKUP)) {
            // if produce|consume right is authorized then we authorize lookup
            facts.add(topicOperationFact(TopicOperation.PRODUCE));
            facts.add(topicOperationFact(TopicOperation.CONSUME));
        }
        Set<String> rules = Set.of("right($tenant, $namespace, $topic, $operation) <- topic($tenant, $namespace, $topic), topic_operation($operation)," + topicOperations + ".contains($operation)");
        Set<String> checks = Set.of("check if right(" + topicFragment(topicName) + "," + topicOperationFragment(operation) + ")");
        return authorize(() -> defaultProvider.allowTopicOperationAsync(topicName, role, operation, authData), true, "allowTopicOperationAsync(" + operation + " -> " + topicName + ")", role, authData, facts, rules, checks);
    }

    @Override
    public CompletableFuture<Boolean> allowTopicPolicyOperationAsync(TopicName topicName, String role, PolicyName policy, PolicyOperation operation, AuthenticationDataSource authData) {
        Set<String> facts = Set.of(
                topicFact(topicName),
                topicPolicyOperationFact(policy, operation)
        );
        Set<String> rules = Set.of("right($tenant, $namespace, $topic, $operation) <- topic($tenant, $namespace, $topic), topic_operation($operation), " + policiesOperations + ".contains($operation)");
        Set<String> checks = Set.of("check if right(" + topicFragment(topicName) + "," + topicPolicyOperationFragment(policy, operation) + ")");
        return authorize(() -> defaultProvider.allowTopicPolicyOperationAsync(topicName, role, policy, operation, authData), true, "allowTopicPolicyOperationAsync(" + policy + "." + operation + " -> " + topicName + ")", role, authData, facts, rules, checks);
    }

    // those management functions will be performed outside of the authorization provider
    @Override
    public CompletableFuture<Void> grantPermissionAsync(NamespaceName namespace, Set<AuthAction> actions, String role, String authDataJson) {
        return defaultProvider.grantPermissionAsync(namespace, actions, role, authDataJson);
    }

    @Override
    public CompletableFuture<Void> grantSubscriptionPermissionAsync(NamespaceName namespace, String subscriptionName, Set<String> roles, String authDataJson) {
        return defaultProvider.grantSubscriptionPermissionAsync(namespace, subscriptionName, roles, authDataJson);
    }

    @Override
    public CompletableFuture<Void> revokeSubscriptionPermissionAsync(NamespaceName namespace, String subscriptionName, String role, String authDataJson) {
        return defaultProvider.revokeSubscriptionPermissionAsync(namespace, subscriptionName, role, authDataJson);
    }

    @Override
    public CompletableFuture<Void> grantPermissionAsync(TopicName topicName, Set<AuthAction> actions, String role, String authDataJson) {
        return defaultProvider.grantPermissionAsync(topicName, actions, role, authDataJson);
    }

    @Override
    public void close() throws IOException {
        // noop
    }
}