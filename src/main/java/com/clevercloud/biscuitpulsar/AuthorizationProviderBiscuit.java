package com.clevercloud.biscuitpulsar;

import com.clevercloud.biscuit.datalog.RunLimits;
import com.clevercloud.biscuit.error.Error;
import com.clevercloud.biscuit.token.Biscuit;
import com.clevercloud.biscuit.token.Verifier;
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
import java.time.Duration;
import java.util.Base64;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import static com.clevercloud.biscuitpulsar.formatter.BiscuitFormatter.*;
import static io.vavr.API.Left;

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
        runLimits = new RunLimits();
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

    public Either<Error, Verifier> verifierFromBiscuit(String role) {
        Either<Error, Biscuit> deser = Biscuit.from_sealed(
                Base64.getUrlDecoder().decode(role.substring("biscuit:".length())),
                AuthenticationProviderBiscuit.SEALING_KEY.getBytes()
        );
        if (deser.isLeft()) {
            Error e = deser.getLeft();
            log.error("Failed to deserialize Biscuit from sealed [{}] due to [{}].", role, e.toString());
            return Left(e);
        }

        Biscuit token = deser.get();
        return token.verify_sealed();
    }

    @Override
    public void initialize(ServiceConfiguration conf, PulsarResources pulsarResources) throws IOException {
        this.conf = conf;
        this.pulsarResources = pulsarResources;
        defaultProvider = new PulsarAuthorizationProvider(conf, pulsarResources);
    }

    @Override
    public CompletableFuture<Boolean> canProduceAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.canProduceAsync(topicName, role, authenticationData);
        }

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            return CompletableFuture.failedFuture(new Exception(res.getLeft().toString()));
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_fact(topicFact(topicName)).get();
        verifier.add_fact(topicOperationFact(topicName, TopicOperation.PRODUCE)).get();
        verifier.add_rule("right(#authority, $tenant, $namespace, $topic, #produce) <- right(#authority, #admin), topic_operation(#ambient, $tenant, $namespace, $topic, #produce)").get();
        verifier.add_check("check if right(#authority," + topicFactFragment(topicName) + "," + topicOperationSymbol(TopicOperation.PRODUCE)).get();
        verifier.allow();

        Either verifierResult = verifier.verify(runLimits);
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit canProduceAsync on [{}] NOT authorized for role [{}]: {}", topicName, role, verifierResult.getLeft());
            return isSuperUser(role, authenticationData, this.conf);
        } else {
            log.debug("Biscuit canProductAsync on [{}] authorized.", topicName);
            return CompletableFuture.completedFuture(true);
        }
    }

    @Override
    public CompletableFuture<Boolean> canConsumeAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData, String subscription) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.canConsumeAsync(topicName, role, authenticationData, subscription);
        }

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            return CompletableFuture.failedFuture(new Exception(res.getLeft().toString()));
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_fact(topicFact(topicName)).get();
        verifier.add_fact(topicOperationFact(topicName, TopicOperation.CONSUME)).get();
        verifier.add_rule("right(#authority, $tenant, $namespace, $topic, #consume) <- right(#authority, #admin), topic_operation(#ambient, $tenant, $namespace, $topic, #consume)").get();
        verifier.add_check("check if right(#authority," + topicFactFragment(topicName) + "," + topicOperationSymbol(TopicOperation.CONSUME)).get();
        verifier.allow();

        Either verifierResult = verifier.verify(runLimits);
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit canConsumeAsync on [{}] NOT authorized for role [{}]: {}", topicName, role, verifierResult.getLeft());
            return isSuperUser(role, authenticationData, this.conf);
        } else {
            log.debug("Biscuit canConsumeAsync on [{}] authorized.", topicName);
            return CompletableFuture.completedFuture(true);
        }
    }

    @Override
    public CompletableFuture<Boolean> canLookupAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.canLookupAsync(topicName, role, authenticationData);
        }

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            return CompletableFuture.failedFuture(new Exception(res.getLeft().toString()));
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_fact(topicFact(topicName)).get();
        verifier.add_fact(topicOperationFact(topicName, TopicOperation.LOOKUP)).get();
        verifier.add_rule("right(#authority, $tenant, $namespace, $topic, #lookup) <- right(#authority, #admin), topic_operation(#ambient, $tenant, $namespace, $topic, #lookup)").get();
        verifier.add_check("check if right(#authority," + topicFactFragment(topicName) + "," + topicOperationSymbol(TopicOperation.LOOKUP)).get();
        verifier.allow();

        Either verifierResult = verifier.verify(runLimits);
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit canLookupAsync on [{}] NOT authorized for role [{}]: {}", topicName, role, verifierResult.getLeft());
            return isSuperUser(role, authenticationData, this.conf);
        } else {
            log.debug("Biscuit canLookupAsync on [{}] authorized.", topicName);
            return CompletableFuture.completedFuture(true);
        }
    }

    @Override
    //FIXME: should be reworked
    public CompletableFuture<Boolean> allowFunctionOpsAsync(NamespaceName namespaceName, String role, AuthenticationDataSource authenticationData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowFunctionOpsAsync(namespaceName, role, authenticationData);
        }

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            return CompletableFuture.failedFuture(new Exception(res.getLeft().toString()));
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_fact(namespaceFact(namespaceName)).get();
        verifier.add_operation("functions");
        // should we have #namespace here? why not have #topic for topic rights to be coherent?
        verifier.add_check("check if right(#authority, #namespace," + namespaceFactFragment(namespaceName) + ",#functions)").get();
        verifier.allow();

        Either verifierResult = verifier.verify(runLimits);
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit allowFunctionOpsAsync on [{}] NOT authorized for role [{}]: {}", namespaceName, role, verifierResult.getLeft());
            return isSuperUser(role, authenticationData, this.conf);
        } else {
            log.debug("Biscuit allowFunctionOpsAsync on [{}] authorized.", namespaceName);
            return CompletableFuture.completedFuture(true);
        }
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
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.isSuperUser(role, authenticationData, serviceConfiguration);
        }

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            return CompletableFuture.failedFuture(new Exception(res.getLeft().toString()));
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_check("check if right(#authority, #admin)").get();
        verifier.allow();

        Either verifierResult = verifier.verify(runLimits);
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit isSuperUser NOT authorized for role [{}]: {}", role, verifierResult.getLeft());
            return CompletableFuture.completedFuture(false);
        } else {
            log.debug("Biscuit isSuperUser authorized.");
            return CompletableFuture.completedFuture(true);
        }
    }

    @Override
    public CompletableFuture<Boolean> allowTenantOperationAsync(String tenantName, String role, TenantOperation operation, AuthenticationDataSource authData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowTenantOperationAsync(tenantName, role, operation, authData);
        }

        return isSuperUser(role, authData, this.conf);
    }

    @Override
    public CompletableFuture<Boolean> allowNamespaceOperationAsync(NamespaceName namespaceName, String role, NamespaceOperation operation, AuthenticationDataSource authData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowNamespaceOperationAsync(namespaceName, role, operation, authData);
        }

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            return CompletableFuture.failedFuture(new Exception(res.getLeft().toString()));
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_fact(namespaceFact(namespaceName)).get();
        verifier.add_fact(namespaceOperationFact(namespaceName, operation)).get();
        verifier.add_rule("right(#authority, $tenant, $namespace, $operation) <- right(#authority, #admin), namespace_operation(#ambient, $tenant, $namespace, $operation), " + namespaceOperations + ".contains($operation)").get();
        verifier.add_check("check if right(#authority," + namespaceFactFragment(namespaceName) + "," + namespaceOperationSymbol(operation) + ")").get();
        verifier.allow();

        Either verifierResult = verifier.verify(runLimits);
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit allowNamespaceOperationAsync [{}] on [{}] NOT authorized for role [{}]: {}", operation, namespaceName, role, verifierResult.getLeft());
            return isSuperUser(role, authData, this.conf);
        } else {
            log.debug("Biscuit allowNamespaceOperationAsync [{}] on [{}] authorized.", operation, namespaceName);
            return CompletableFuture.completedFuture(true);
        }
    }

    @Override
    public CompletableFuture<Boolean> allowNamespacePolicyOperationAsync(NamespaceName namespaceName, PolicyName policy, PolicyOperation operation, String role, AuthenticationDataSource authData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowNamespacePolicyOperationAsync(namespaceName, policy, operation, role, authData);
        }

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            return CompletableFuture.failedFuture(new Exception(res.getLeft().toString()));
        }

        Verifier verifier = res.get();
        verifier.set_time();

        verifier.add_fact(namespaceFact(namespaceName)).get();
        verifier.add_fact(namespacePolicyOperationFact(namespaceName, policy, operation)).get();
        verifier.add_rule("right(#authority, $tenant, $namespace, $operation) <- right(#authority, #admin), namespace_operation(#ambient, $tenant, $namespace, $operation), " + policiesOperations + ".contains($operation)").get();
        verifier.add_check("check if right(#authority," + namespaceFactFragment(namespaceName) + "," + policyOperationFact(policy, operation) + ")").get();
        verifier.allow();

        Either verifierResult = verifier.verify(runLimits);
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit allowNamespacePolicyOperationAsync [{}]:[{}] on [{}] NOT authorized for role [{}]: {}", policy, operation, namespaceName, role, verifierResult.getLeft());
            return isSuperUser(role, authData, this.conf);
        } else {
            log.debug("Biscuit allowNamespacePolicyOperationAsync [{}]:[{}] on [{}] authorized.", policy, operation, namespaceName);
            return CompletableFuture.completedFuture(true);
        }
    }

    @Override
    public CompletableFuture<Boolean> allowTopicOperationAsync(TopicName topicName, String role,
                                                               TopicOperation operation,
                                                               AuthenticationDataSource authData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowTopicOperationAsync(topicName, role, operation, authData);
        }

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            return CompletableFuture.failedFuture(new Exception(res.getLeft().toString()));
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_fact(topicFact(topicName)).get();
        verifier.add_fact(topicOperationFact(topicName, operation)).get();

        // if produce|consume right is authorized then we authorize lookup
        if (operation.equals(TopicOperation.LOOKUP)) {
            verifier.add_fact(topicOperationFact(topicName, TopicOperation.PRODUCE)).get();
            verifier.add_fact(topicOperationFact(topicName, TopicOperation.CONSUME)).get();
        }

        verifier.add_rule("right(#authority, $tenant, $namespace, $topic, $operation) <- right(#authority, #admin), topic_operation(#ambient, $tenant, $namespace, $topic, $operation)," + topicOperations + ".contains($operation)").get();
        verifier.add_check("check if right( #authority," + topicFactFragment(topicName) + "," + topicOperationSymbol(operation) + ")").get();
        verifier.allow();

        Either verifierResult = verifier.verify(runLimits);
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit allowTopicOperationAsync [{}] on [{}] NOT authorized for role [{}]: {}", operation, topicName, role, verifierResult.getLeft());
            return isSuperUser(role, authData, this.conf);
        } else {
            log.debug("Biscuit allowTopicOperationAsync [{}] on [{}] authorized.", operation, topicName);
            return CompletableFuture.completedFuture(true);
        }
    }

    @Override
    public CompletableFuture<Boolean> allowTopicPolicyOperationAsync(TopicName topicName, String role, PolicyName policy, PolicyOperation operation, AuthenticationDataSource authData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowTopicPolicyOperationAsync(topicName, role, policy, operation, authData);
        }

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            return CompletableFuture.failedFuture(new Exception(res.getLeft().toString()));
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_fact(topicFact(topicName)).get();
        verifier.add_fact(topicPolicyOperationFact(topicName, policy, operation)).get();
        verifier.add_rule("right(#authority, $tenant, $namespace, $topic, $operation) <- right(#authority, #admin), topic_operation(#ambient, $tenant, $namespace, $topic, $operation), " + policiesOperations + ".contains($operation)").get();
        verifier.add_check("check if right(#authority," + topicFactFragment(topicName) + "," + policyOperationFact(policy, operation) + ")").get();
        verifier.allow();

        Either verifierResult = verifier.verify(runLimits);
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit allowTopicPolicyOperationAsync [{}]:[{}] on [{}] NOT authorized for role [{}]: {}", policy, operation, topicName, role, verifierResult.getLeft());
            return isSuperUser(role, authData, this.conf);
        } else {
            log.debug("Biscuit allowTopicPolicyOperationAsync [{}]:[{}] on [{}] authorized.", policy, operation, topicName);
            return CompletableFuture.completedFuture(true);
        }
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