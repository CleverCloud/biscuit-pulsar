package com.clevercloud.biscuitpulsar;

import com.clevercloud.biscuit.crypto.KeyPair;
import com.clevercloud.biscuit.datalog.SymbolTable;
import com.clevercloud.biscuit.error.Error;
import com.clevercloud.biscuit.token.Biscuit;
import com.clevercloud.biscuit.token.Verifier;
import com.clevercloud.biscuit.token.builder.Block;
import com.clevercloud.biscuit.token.builder.Fact;
import com.clevercloud.biscuit.token.builder.Predicate;
import io.vavr.control.Either;
import io.vavr.control.Option;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authorization.AuthorizationProvider;
import org.apache.pulsar.broker.authorization.PulsarAuthorizationProvider;
import org.apache.pulsar.broker.cache.ConfigurationCacheService;
import org.apache.pulsar.common.naming.NamespaceName;
import org.apache.pulsar.common.naming.TopicName;
import org.apache.pulsar.common.policies.data.AuthAction;
import org.apache.pulsar.common.policies.data.NamespaceOperation;
import org.apache.pulsar.common.policies.data.PolicyName;
import org.apache.pulsar.common.policies.data.PolicyOperation;
import org.apache.pulsar.common.policies.data.TenantOperation;
import org.apache.pulsar.common.policies.data.TopicOperation;
import org.apache.pulsar.common.util.FutureUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;

import static com.clevercloud.biscuit.token.builder.Utils.*;
import static io.vavr.API.*;

public class AuthorizationProviderBiscuit implements AuthorizationProvider {
    private static final Logger log = LoggerFactory.getLogger(AuthorizationProviderBiscuit.class);

    public ServiceConfiguration conf;
    public ConfigurationCacheService configCache;
    private PulsarAuthorizationProvider defaultProvider;

    public AuthorizationProviderBiscuit() {
        warmUp();
    }

    public AuthorizationProviderBiscuit(ServiceConfiguration conf, ConfigurationCacheService configCache)
            throws IOException {
        initialize(conf, configCache);
        warmUp();
    }

    /**
     * This method is called when creating new AuthorizationProviderBiscuit to warm up JVM datalog engine and get rid
     * of timeouts that can occurs during first Verifier.verify()
     */
    private void warmUp() {
        SecureRandom rng = new SecureRandom();
        KeyPair root = new KeyPair(rng);
        SymbolTable symbols = Biscuit.default_symbol_table();

        String tenant = "tenantTest";
        String namespace = "namespaceTest";
        String topic = "topicTest";

        for (int i = 0; i < 1000; i++){
            Block authority_builder = new Block(0, symbols);
            authority_builder.add_rule(rule("right",
                    Arrays.asList(s("authority"), string(tenant), string(namespace), string(topic), s("produce")),
                    Arrays.asList(pred("topic_operation", Arrays.asList(s("ambient"), string(tenant), string(namespace), string(topic), s("produce"))))));
            Verifier v = Verifier.make(Biscuit.make(rng, root, symbols, authority_builder.build()).get(), Option.of(root.public_key())).get();
            v.verify();
        }
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
    public void initialize(ServiceConfiguration conf, ConfigurationCacheService configCache) throws IOException {
        this.conf = conf;
        this.configCache = configCache;
        defaultProvider = new PulsarAuthorizationProvider(conf, configCache);
    }

    @Override
    public CompletableFuture<Boolean> canProduceAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.canProduceAsync(topicName, role, authenticationData);
        }

        CompletableFuture<Boolean> isAuthorizedFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            isAuthorizedFuture.complete(false);
            return isAuthorizedFuture;
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_fact("topic(#ambient, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\", \""+topicName.getLocalName()+"\")").get();
        verifier.add_fact("topic_operation(#ambient, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\", \""+topicName.getLocalName()+"\", #produce)").get();
        verifier.add_rule("right(#authority, $tenant, $namespace, $topic, #produce) <- " +
                "right(#authority, #admin), topic_operation(#ambient, $tenant, $namespace, $topic, #produce)").get();
        verifier.add_check("check if right(#authority, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\", \""+topicName.getLocalName()+"\", #produce)").get();
        verifier.allow();

        Either verifierResult = verifier.verify();
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit canProduceAsync on [{}] NOT authorized for role [{}]: {}", topicName.toString(), role, verifierResult.getLeft());
            return isSuperUser(role, authenticationData, conf);
        } else {
            log.debug("Biscuit canProduceAsync on [{}] authorized.", topicName.toString());
            isAuthorizedFuture.complete(verifierResult.isRight());
            return isAuthorizedFuture;
        }
    }

    @Override
    public CompletableFuture<Boolean> canConsumeAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData, String subscription) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.canConsumeAsync(topicName, role, authenticationData, subscription);
        }

        CompletableFuture<Boolean> isAuthorizedFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            isAuthorizedFuture.complete(false);
            return isAuthorizedFuture;
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_fact("topic(#ambient, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\", \""+topicName.getLocalName()+"\")").get();
        verifier.add_fact("topic_operation(#ambient, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\", \""+topicName.getLocalName()+"\", #consume)").get();
        verifier.add_rule("right(#authority, $tenant, $namespace, $topic, #consume) <- " +
                "right(#authority, #admin), topic_operation(#ambient, $tenant, $namespace, $topic, #consume)").get();
        verifier.add_check("check if right(#authority, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\", \""+topicName.getLocalName()+"\", #consume)").get();
        verifier.allow();

        Either verifierResult = verifier.verify();
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit canConsumeAsync on [{}] NOT authorized for role [{}]: {}", topicName.toString(), role, verifierResult.getLeft());
            return isSuperUser(role, authenticationData, conf);
        } else {
            log.debug("Biscuit canConsumeAsync on [{}] authorized.", topicName.toString());
            isAuthorizedFuture.complete(verifierResult.isRight());
            return isAuthorizedFuture;
        }
    }

    @Override
    public CompletableFuture<Boolean> canLookupAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.canLookupAsync(topicName, role, authenticationData);
        }

        CompletableFuture<Boolean> isAuthorizedFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            isAuthorizedFuture.complete(false);
            return isAuthorizedFuture;
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_fact("topic(#ambient, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\", \""+topicName.getLocalName()+"\")").get();
        verifier.add_fact("topic_operation(#ambient, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\", \""+topicName.getLocalName()+"\", #lookup)").get();
        verifier.add_rule("right(#authority, $tenant, $namespace, $topic, #lookup) <- " +
                "right(#authority, #admin), topic_operation(#ambient, $tenant, $namespace, $topic, #lookup)").get();
        verifier.add_check("check if right(#authority, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\", \""+topicName.getLocalName()+"\", #lookup)").get();
        verifier.allow();

        Either verifierResult = verifier.verify();
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit canLookupAsync on [{}] NOT authorized for role [{}]: {}", topicName.toString(), role, verifierResult.getLeft());
            return isSuperUser(role, authenticationData, conf);
        } else {
            log.debug("Biscuit canLookupAsync on [{}] authorized.", topicName.toString());
            isAuthorizedFuture.complete(verifierResult.isRight());
            return isAuthorizedFuture;
        }
    }

    @Override
    public CompletableFuture<Boolean> allowFunctionOpsAsync(NamespaceName namespaceName, String role, AuthenticationDataSource authenticationData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowFunctionOpsAsync(namespaceName, role, authenticationData);
        }

        CompletableFuture<Boolean> isAuthorizedFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            isAuthorizedFuture.complete(false);
            return isAuthorizedFuture;
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_fact("namespace(#ambient, \""+namespaceName.getTenant()+"\", \""+namespaceName.getLocalName()+"\")").get();
        verifier.add_operation("functions");
        // should we have #namespace here? why not have #topic for topic rights to be coherent?
        verifier.add_check("check if right(#authority, #namespace, \""+namespaceName.getTenant()+"\", \""+namespaceName.getLocalName()+"\", #functions)").get();
        verifier.allow();

        Either verifierResult = verifier.verify();
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit allowFunctionOpsAsync on [{}] NOT authorized for role [{}]: {}", namespaceName.toString(), role, verifierResult.getLeft());
            return isSuperUser(role, authenticationData, conf);
        } else {
            log.debug("Biscuit allowFunctionOpsAsync on [{}] authorized.", namespaceName.toString());
            isAuthorizedFuture.complete(verifierResult.isRight());
            return isAuthorizedFuture;
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

        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            permissionFuture.complete(false);
            return permissionFuture;
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_check("check if right(#authority, #admin)").get();
        verifier.allow();

        Either verifierResult = verifier.verify();
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit isSuperUser NOT authorized for role [{}]: {}", role, verifierResult.getLeft());
        } else {
            log.debug("Biscuit isSuperUser authorized.");
        }

        permissionFuture.complete(verifierResult.isRight());

        return permissionFuture;
    }

    @Override
    public CompletableFuture<Boolean> allowTenantOperationAsync(String tenantName, String role, TenantOperation operation, AuthenticationDataSource authData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowTenantOperationAsync(tenantName, role, operation, authData);
        }

        return isSuperUser(role, authData, conf).thenCompose(isSuperUser -> {
            if (isSuperUser) {
                return CompletableFuture.completedFuture(true);
            } else {
                return FutureUtil.failedFuture(new IllegalStateException("allowTenantOperationAsync is not implemented for biscuit."));
            }
        });
    }

    @Override
    public CompletableFuture<Boolean> allowNamespaceOperationAsync(NamespaceName namespaceName, String role, NamespaceOperation operation, AuthenticationDataSource authData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowNamespaceOperationAsync(namespaceName, role, operation, authData);
        }

        CompletableFuture<Boolean> isAuthorizedFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            isAuthorizedFuture.complete(false);
            return isAuthorizedFuture;
        }

        Verifier verifier = res.get();
        verifier.set_time();

        Optional<NamespaceOperation> operationName = Stream.of(NamespaceOperation.values()).filter(e -> e == operation).findFirst();
        if (operationName.isPresent()) {
            verifier.add_fact("namespace(#ambient, \""+namespaceName.getTenant()+"\", \""+namespaceName.getLocalName()+"\")").get();
            verifier.add_fact("namespace_operation(#ambient, \""+
                    namespaceName.getTenant()+
                    "\", \"" + namespaceName.getLocalName()+
                    "\", #"+operationName.get().toString().toLowerCase()+")").get();

            // what about operations get_permission, grant_permission and revoke_permission?
            verifier.add_rule("right(#authority, $tenant, $namespace, $operation) <- " +
                    "right(#authority, #admin), namespace_operation(#ambient, $tenant, $namespace, $operation), " +
                    "[ #create_topic, #get_topic, #get_topics, #delete_topic, #add_bundle, #delete_bundle, " +
                      "#get_bundle, #clear_backlog, #unsubscribe ].contains($operation)").get();

            // NamespaceOperation CREATE_TOPIC returns operation "create_topic"
            verifier.add_check("check if right(#authority, \""+namespaceName.getTenant()+"\", \""+namespaceName.getLocalName()+"\", #" + operationName.get().toString().toLowerCase() + ")").get();
            verifier.allow();
        } else {
            return isSuperUser(role, authData, conf);
        }

        Either verifierResult = verifier.verify();
        log.debug(verifier.print_world());

        if (verifierResult.isLeft()) {
            log.debug("Biscuit allowNamespaceOperationAsync [{}] on [{}] NOT authorized for role [{}]: {}", operation.toString(), namespaceName.toString(), role, verifierResult.getLeft());
            return isSuperUser(role, authData, conf);
        } else {
            log.debug("Biscuit allowNamespaceOperationAsync [{}] on [{}] authorized.", operation.toString(), namespaceName.toString());
            isAuthorizedFuture.complete(verifierResult.isRight());
            return isAuthorizedFuture;
        }
    }

    @Override
    public CompletableFuture<Boolean> allowNamespacePolicyOperationAsync(NamespaceName namespaceName, PolicyName policy, PolicyOperation operation, String role, AuthenticationDataSource authData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowNamespacePolicyOperationAsync(namespaceName, policy, operation, role, authData);
        }

        CompletableFuture<Boolean> isAuthorizedFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            isAuthorizedFuture.complete(false);
            return isAuthorizedFuture;
        }

        Verifier verifier = res.get();
        verifier.set_time();

        Optional<PolicyName> policyName = Stream.of(PolicyName.values()).filter(e -> e == policy).findFirst();
        if (policyName.isPresent()) {
            verifier.add_fact("namespace(#ambient, \""+namespaceName.getTenant()+"\", \""+namespaceName.getLocalName()+"\")").get();
            // PolicyName OFFLOAD, operation READ returns operation "offload_read"
            verifier.add_fact("namespace_operation(#ambient, \""+ namespaceName.getTenant() +
                "\", \"" + namespaceName.getLocalName() +
                "\", #"+policyName.get().toString().toLowerCase() +
                "_" + operation.toString().toLowerCase()+")"
            ).get();
            verifier.add_rule("right(#authority, $tenant, $namespace, $operation) <- " +
                    "right(#authority, #admin), namespace_operation(#ambient, $tenant, $namespace, $operation), " +
                    "[ "+
                            "#all_read, "+
                            //"#all_write"
                            //"#anty_affinity_write"
                            "#anty_affinity_read, "+
                            "#backlog_read, "+
                            "#backlog_write, "+
                            "#compaction_read, "+
                            "#compaction_write, "+
                            "#delayed_delivery_read, "+
                            "#delayed_delivery_write, "+
                            "#deduplication_read, "+
                            "#deduplication_write, "+
                            "#max_consumers_read, "+
                            "#max_consumers_write, "+
                            "#max_producers_read, "+
                            "#max_producers_write, "+
                            "#max_unacked_read, "+
                            "#max_unacked_write, "+
                            "#offload_read, "+
                            //"#offload_write"
                            "#persistence_read, "+
                            "#persistence_write, "+
                            "#rate_write, "+
                            "#rate_read, "+
                            "#retention_read, "+
                            "#retention_write, "+
                            "#replication_read, "+
                            //"#replication_write"
                            "#replication_rate_read, "+
                            //"#replication_rate_write"
                            "#schema_compatibility_strategy_read, "+
                            "#schema_compatibility_strategy_write, "+
                            "#subscription_auth_mode_read, "+
                            "#subscription_auth_mode_write, "+
                            "#encryption_read, "+
                            "#encryption_write, "+
                            "#ttl_read, "+
                            "#ttl_write "
                                    +"].contains($operation)").get();


            // PolicyName OFFLOAD, operation READ returns operation "offload_read"
            verifier.add_check("check if right(#authority, \""+namespaceName.getTenant()+"\", \""+namespaceName.getLocalName()+"\", #"+policyName.get().toString().toLowerCase() + "_" + operation.toString().toLowerCase()+")").get();
            verifier.allow();

        } else {
            return isSuperUser(role, authData, conf);
        }

        Either verifierResult = verifier.verify();
        log.debug(verifier.print_world());
        if (verifierResult.isLeft()) {
            log.debug("Biscuit allowNamespacePolicyOperationAsync [{}]:[{}] on [{}] NOT authorized for role [{}]: {}", policy.toString(), operation.toString(), namespaceName.toString(), role, verifierResult.getLeft());
            return isSuperUser(role, authData, conf);
        } else {
            log.debug("Biscuit allowNamespacePolicyOperationAsync [{}]:[{}] on [{}] authorized.", policy.toString(), operation.toString(), namespaceName.toString());
            isAuthorizedFuture.complete(true);
            return isAuthorizedFuture;
        }
    }

    @Override
    public CompletableFuture<Boolean> allowTopicOperationAsync(TopicName topicName, String role,
                                                               TopicOperation operation,
                                                               AuthenticationDataSource authData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowTopicOperationAsync(topicName, role, operation, authData);
        }

        CompletableFuture<Boolean> isAuthorizedFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            isAuthorizedFuture.complete(false);
            return isAuthorizedFuture;
        }

        Verifier verifier = res.get();
        verifier.set_time();
        verifier.add_fact("topic(#ambient, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\", \""+topicName.getLocalName()+"\")").get();
        verifier.add_fact("topic_operation(#ambient, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\", \""+topicName.getLocalName()+"\", #"+operation.toString().toLowerCase()+")").get();

        // if produce|consume right is authorized then we authorize lookup
        if (operation.equals(TopicOperation.LOOKUP)) {
            verifier.add_fact("topic_operation(#ambient, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\", \""+topicName.getLocalName()+"\", #consume)").get();
            verifier.add_fact("topic_operation(#ambient, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\", \""+topicName.getLocalName()+"\", #produce)").get();
        }

        verifier.add_rule("right(#authority, $tenant, $namespace, $topic, $operation) <- " +
                "right(#authority, #admin), topic_operation(#ambient, $tenant, $namespace, $topic, $operation)," +
                "[" +
                    "#lookup, "+
                    "#produce, "+
                    "#consume, "+
                    "#compact, "+
                    "#expire_messages, "+
                    "#offload, "+
                    "#peek_messages, "+
                    "#reset_cursor, "+
                    "#skip, "+
                    "#terminate, "+
                    //"unload",
                    //"grant_permission",
                    //"get_permission",
                    //"revoke_permission",
                    //"add_bundle_range",
                    //"get_bundle_range",
                    //"delete_bundle_range",
                    "#subscribe, "+
                    "#get_subscriptions, "+
                    "#unsubscribe, "+
                    "#get_stats"+
                " ].contains($operation)").get();

        verifier.add_check("check if right( #authority, \""+
                        topicName.getTenant()+"\", \""+
                        topicName.getNamespacePortion()+"\", \""+
                        topicName.getLocalName()+
                        "\", #"+operation.toString().toLowerCase()+")").get();

        verifier.allow();

        Either verifierResult = verifier.verify();
        log.debug(verifier.print_world());
        if (verifierResult.isLeft()) {
            log.debug("Biscuit allowTopicOperationAsync [{}] on [{}] NOT authorized for role [{}]: {}", operation.toString(), topicName.toString(), role, verifierResult.getLeft());
            return isSuperUser(role, authData, conf);
        } else {
            log.debug("Biscuit allowTopicOperationAsync [{}] on [{}] authorized.", operation.toString(), topicName.toString());
            isAuthorizedFuture.complete(verifierResult.isRight());
            return isAuthorizedFuture;
        }
    }

    @Override
    public CompletableFuture<Boolean> allowTopicPolicyOperationAsync(TopicName topicName, String role, PolicyName policy, PolicyOperation operation, AuthenticationDataSource authData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowTopicPolicyOperationAsync(topicName, role, policy, operation, authData);
        }

        CompletableFuture<Boolean> isAuthorizedFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            isAuthorizedFuture.complete(false);
            return isAuthorizedFuture;
        }

        Verifier verifier = res.get();
        verifier.set_time();

        Optional<PolicyName> policyName = Stream.of(PolicyName.values()).filter(e -> e == policy).findFirst();
        if (policyName.isPresent()) {
            verifier.add_fact("namespace(#ambient, \""+topicName.getTenant()+"\", \""+topicName.getNamespacePortion()+"\")").get();
            // PolicyName OFFLOAD, operation READ returns operation "offload_read"
            verifier.add_fact("namespace_operation(#ambient, \"" +
                    topicName.getTenant() +
                    "\", \"" + topicName.getNamespacePortion() +
                    "\", #"+policyName.get().toString().toLowerCase() +
                    "_" + operation.toString().toLowerCase()+")"
            ).get();
            verifier.add_rule("right(#authority, $tenant, $namespace, $operation) <- " +
                    "right(#authority, #admin), namespace_operation(#ambient, $tenant, $namespace, $operation), " +
                    "[#partition_read, #partition_write].contains($operation)"
            ).get();
            // PolicyName OFFLOAD, operation READ returns operation "offload_read"
            verifier.add_check("check if right( #authority, \""+
                    topicName.getTenant()+"\", \""+
                    topicName.getNamespacePortion()+
                    "\",  #"+policyName.get().toString().toLowerCase() + "_" + operation.toString().toLowerCase()+")").get();

            verifier.allow();
        } else {
            return isSuperUser(role, authData, conf);
        }

        Either verifierResult = verifier.verify();
        log.debug(verifier.print_world());
        if (verifierResult.isLeft()) {
            log.debug("Biscuit allowTopicPolicyOperationAsync [{}]:[{}] on [{}] NOT authorized for role [{}]: {}", policy.toString(), operation.toString(), topicName.getNamespacePortion(), role, verifierResult.getLeft());
            return isSuperUser(role, authData, conf);

        } else {
            log.debug("Biscuit allowTopicPolicyOperationAsync [{}]:[{}] on [{}] authorized.", policy.toString(), operation.toString(), topicName.getNamespacePortion());
            isAuthorizedFuture.complete(verifierResult.isRight());
            return isAuthorizedFuture;
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