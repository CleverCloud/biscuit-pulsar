package com.clevercloud.biscuitpulsar;

import com.clevercloud.biscuit.error.Error;
import com.clevercloud.biscuit.token.Biscuit;
import com.clevercloud.biscuit.token.Verifier;
import com.clevercloud.biscuit.token.builder.Caveat;
import com.clevercloud.biscuit.token.builder.Fact;
import com.clevercloud.biscuit.token.builder.Predicate;
import io.vavr.control.Either;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;

import static com.clevercloud.biscuit.token.builder.Utils.*;
import static io.vavr.API.Left;
import static io.vavr.API.Right;

public class AuthorizationProviderBiscuit implements AuthorizationProvider {
    private static final Logger log = LoggerFactory.getLogger(AuthorizationProviderBiscuit.class);

    public ServiceConfiguration conf;
    public ConfigurationCacheService configCache;
    private PulsarAuthorizationProvider defaultProvider;

    public AuthorizationProviderBiscuit() {
    }

    public AuthorizationProviderBiscuit(ServiceConfiguration conf, ConfigurationCacheService configCache)
            throws IOException {
        initialize(conf, configCache);
    }

    private Fact topic(TopicName topicName) {
        return fact("topic", Arrays.asList(s("ambient"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName())));
    }

    private Fact subscription(TopicName topicName, String subscription) {
        return fact("subscription", Arrays.asList(s("ambient"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), string(subscription)));
    }

    private Predicate topicRight(TopicName topicName, String right) {
        return pred("right", Arrays.asList(s("authority"), s("topic"),
                string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), s(right)));
    }

    private Fact namespace(NamespaceName namespaceName) {
        return fact("namespace", Arrays.asList(s("ambient"), string(namespaceName.getTenant()), string(namespaceName.getLocalName())));
    }

    private Predicate namespaceOperationRight(NamespaceName namespaceName, String right) {
        return pred("right", Arrays.asList(s("authority"), s("namespace"),
                string(namespaceName.getTenant()), string(namespaceName.getLocalName()), s(right)));
    }

    private Predicate topicSubscriptionRight(TopicName topicName, String subscription, String right) {
        return pred("right", Arrays.asList(s("authority"), s("topic"),
                string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), s(right), string(subscription)));
    }

    public Either<Error, Verifier> verifierFromBiscuit(String role) {
        Either<Error, Biscuit> deser = Biscuit.from_sealed(
                Base64.getUrlDecoder().decode(role.substring("biscuit:".length())),
                AuthenticationProviderBiscuit.SEALING_KEY.getBytes()
        );
        if (deser.isLeft()) {
            Error e = deser.getLeft();
            log.error(e.toString());
            return Left(e);
        }

        Biscuit token = deser.get();
        Either<Error, Verifier> res = token.verify_sealed();

        if (res.isLeft()) {
            return res;
        }

        Verifier verifier = res.get();
        /*verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("lookup")),
                Arrays.asList(pred("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("produce"))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("lookup")),
                Arrays.asList(pred("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("consume"))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("lookup")),
                Arrays.asList(pred("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("consume"), var(3))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("produce")),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("produce"))),
                        pred("topic", Arrays.asList(s("ambient"), var(0), var(1), var(2)))
                )));
        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("consume")),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("consume"))),
                        pred("topic", Arrays.asList(s("ambient"), var(0), var(1), var(2))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("consume"), var(3)),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("consume"))),
                        pred("topic", Arrays.asList(s("ambient"), var(0), var(1), var(2))),
                        pred("subscription", Arrays.asList(s("ambient"), var(0), var(1), var(2), var(3))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("produce")),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("admin"))),
                        pred("topic", Arrays.asList(s("ambient"), var(0), var(1), var(2))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("consume")),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("admin"))),
                        pred("topic", Arrays.asList(s("ambient"), var(0), var(1), var(2))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("consume"), var(1)),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("admin"))),
                        pred("topic", Arrays.asList(s("ambient"), var(0), var(1), var(2))),
                        pred("subscription", Arrays.asList(s("ambient"), var(0), var(1), var(2), var(3)))
                )));
        */

        //*check_right(#authority, #namespace, $0, $1, $2) <- !ns_operation(#authority, #namespace, $0, $1, $2), right(#authority, #namespace, $0, $1, $2) et `*check_right(#authority, #topic, $0, $1, $2, $3) <- !topic_operation(#authority, #topic, $0, $1, $2, $3), right(#authority, #namespace, $0, $1, $2, $3)

        //log.debug(verifier.print_world());

        return Right(verifier);
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

        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            log.error("could not create verifier {}", res.getLeft().toString());
            permissionFuture.complete(false);
            return permissionFuture;
        }

        Verifier verifier = res.get();

        verifier.add_fact(fact("topic",
                Arrays.asList(s("ambient"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()))));

        verifier.add_fact(fact("topic_operation",
                Arrays.asList(s("ambient"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), s("produce"))));

        verifier.add_rule(constrained_rule("right",
                Arrays.asList(s("authority"), var(0), var(1), var(2), var(3)),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("admin"))),
                        pred("topic_operation", Arrays.asList(s("ambient"), var(0), var(1), var(2), var(3)))
                ),
                Arrays.asList(new com.clevercloud.biscuit.token.builder.constraints.SymbolConstraint.InSet(3, new HashSet<>(Arrays.asList(
                        "produce"
                ))))
        ));

        verifier.add_caveat(new Caveat(Arrays.asList(
                rule("check_right",
                        Arrays.asList(),
                        Arrays.asList(
                                pred("right", Arrays.asList(s("authority"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), s("produce")))
                        )
                )
        )));

        log.debug(verifier.print_world());

        Either verifierResult = verifier.verify();
        if (verifierResult.isLeft()) {
            log.error("produce verifier failure: {}", verifierResult.getLeft());
        } else {
            log.debug("produce request authorized by biscuit token");
        }

        permissionFuture.complete(verifierResult.isRight());

        return permissionFuture;
    }

    @Override
    public CompletableFuture<Boolean> canConsumeAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData, String subscription) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.canConsumeAsync(topicName, role, authenticationData, subscription);
        }

        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            permissionFuture.complete(false);
            return permissionFuture;
        }

        Verifier verifier = res.get();

        verifier.add_fact(fact("topic",
                Arrays.asList(s("ambient"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()))));

        verifier.add_fact(fact("topic_operation",
                Arrays.asList(s("ambient"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), s("consume"))));

        verifier.add_rule(constrained_rule("right",
                Arrays.asList(s("authority"), var(0), var(1), var(2), var(3)),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("admin"))),
                        pred("topic_operation", Arrays.asList(s("ambient"), var(0), var(1), var(2), var(3)))
                ),
                Arrays.asList(new com.clevercloud.biscuit.token.builder.constraints.SymbolConstraint.InSet(3, new HashSet<>(Arrays.asList(
                        "consume"
                ))))
        ));

        verifier.add_caveat(new Caveat(Arrays.asList(
                rule("check_right",
                        Arrays.asList(),
                        Arrays.asList(
                                pred("right", Arrays.asList(s("authority"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), s("consume")))
                        )
                )
        )));

        // add these rules because there are two ways to verify that we can consume: with a right defined on the topic
        // or one defined on the subscription
        /*verifier.add_rule(rule("can_consume", Arrays.asList(s("authority"), s("topic"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName())),
                Arrays.asList(
                        topicSubscriptionRight(topicName, subscription, "consume"))));

        verifier.add_rule(rule("can_consume", Arrays.asList(s("authority"), s("topic"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName())),
                Arrays.asList(
                        topicRight(topicName, "consume"))));

        verifier.add_caveat(caveat(rule(
                "checked_consume_right",
                Arrays.asList(s("topic"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), s("consume")),
                Arrays.asList(
                        pred("can_consume", Arrays.asList(s("authority"), s("topic"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName())))
                )
        )));*/

        log.debug(verifier.print_world());
        Either verifierResult = verifier.verify();
        if (verifierResult.isLeft()) {
            log.error("consume verifier failure: {}", verifierResult.getLeft());
        } else {
            log.debug("consume request authorized by biscuit token");
        }

        permissionFuture.complete(verifierResult.isRight());

        return permissionFuture;
    }

    @Override
    public CompletableFuture<Boolean> canLookupAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.canLookupAsync(topicName, role, authenticationData);
        }

        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            permissionFuture.complete(false);
            return permissionFuture;
        }

        Verifier verifier = res.get();

        verifier.add_fact(fact("topic",
                Arrays.asList(s("ambient"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()))));

        verifier.add_fact(fact("topic_operation",
                Arrays.asList(s("ambient"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), s("lookup"))));

        // topic_operation $3 must be lookup
        verifier.add_rule(constrained_rule("right",
                Arrays.asList(s("authority"), var(0), var(1), var(2), var(3)),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("admin"))),
                        pred("topic_operation", Arrays.asList(s("ambient"), var(0), var(1), var(2), var(3)))
                ),
                Arrays.asList(new com.clevercloud.biscuit.token.builder.constraints.SymbolConstraint.InSet(3, new HashSet<>(Arrays.asList(
                        "lookup"
                ))))
        ));

        verifier.add_caveat(new Caveat(Arrays.asList(
                rule("check_right",
                        Arrays.asList(),
                        Arrays.asList(
                                pred("right", Arrays.asList(s("authority"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), s("lookup")))
                        )
                )
        )));

        log.debug(verifier.print_world());

        Either verifierResult = verifier.verify();
        if (verifierResult.isLeft()) {
            log.error("lookup verifier failure: {}", verifierResult.getLeft());
        } else {
            log.info("lookup authorized by biscuit token");
        }

        permissionFuture.complete(verifierResult.isRight());

        return permissionFuture;
    }

    @Override
    public CompletableFuture<Boolean> allowFunctionOpsAsync(NamespaceName namespaceName, String role, AuthenticationDataSource authenticationData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowFunctionOpsAsync(namespaceName, role, authenticationData);
        }

        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            permissionFuture.complete(false);
            return permissionFuture;
        }

        Verifier verifier = res.get();

        verifier.add_fact(fact("namespace", Arrays.asList(s("ambient"), string(namespaceName.getTenant()), string(namespaceName.getLocalName()))));
        verifier.add_operation("functions");
        verifier.set_time();

        verifier.add_caveat(caveat(rule(
                "checked_allowfunction_right",
                Arrays.asList(string(namespaceName.getTenant()), string(namespaceName.getLocalName())),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("namespace"), string(namespaceName.getTenant()), string(namespaceName.getLocalName()), s("functions")))
                )
        )));

        Either verifierResult = verifier.verify();
        permissionFuture.complete(verifierResult.isRight());

        return permissionFuture;
    }

    @Override
    public CompletableFuture<Boolean> isSuperUser(String role, ServiceConfiguration serviceConfiguration) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.isSuperUser(role, serviceConfiguration);
        }

        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            permissionFuture.complete(false);
            return permissionFuture;
        }

        Verifier verifier = res.get();

        verifier.add_caveat(caveat(rule(
                "checked_issuperuser_right",
                Arrays.asList(s("admin")),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("admin")))
                )
        )));

        log.debug(verifier.print_world());

        Either verifierResult = verifier.verify();
        if (verifierResult.isLeft()) {
            log.error("verifier failure: {}", verifierResult.getLeft());
        } else {
            log.debug("superuser authorized by biscuit token");
        }

        permissionFuture.complete(verifierResult.isRight());

        return permissionFuture;
    }

    @Override
    public CompletableFuture<Boolean> isSuperUser(String role, AuthenticationDataSource authenticationData, ServiceConfiguration serviceConfiguration) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.isSuperUser(role, serviceConfiguration);
        }

        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            permissionFuture.complete(false);
            return permissionFuture;
        }

        Verifier verifier = res.get();

        verifier.add_caveat(caveat(rule(
                "checked_issuperuser_right",
                Arrays.asList(s("admin")),
                Arrays.asList(pred("right", Arrays.asList(s("authority"), s("admin")))))
        ));

        Either verifierResult = verifier.verify();
        if (verifierResult.isLeft()) {
            log.error("verifier failure: {}", verifierResult.getLeft());
        } else {
            log.debug("superuser authorized by biscuit token");
        }

        permissionFuture.complete(verifierResult.isRight());

        return permissionFuture;
    }

    @Override
    public CompletableFuture<Boolean> allowTenantOperationAsync(String tenantName, String originalRole, String role, TenantOperation operation, AuthenticationDataSource authData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowTenantOperationAsync(tenantName, originalRole, originalRole, operation, authData);
        }

        return isSuperUser(role, conf).thenCompose(isSuperUser -> {
            if (isSuperUser) {
                return CompletableFuture.completedFuture(true);
            } else {
                return FutureUtil.failedFuture(new IllegalStateException("allowTenantOperationAsync is not implemented for biscuit."));
            }
        });
    }

    @Override
    public CompletableFuture<Boolean> allowNamespaceOperationAsync(NamespaceName namespaceName, String originalRole, String role, NamespaceOperation operation, AuthenticationDataSource authData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowNamespaceOperationAsync(namespaceName, originalRole, originalRole, operation, authData);
        }

        log.debug(String.format("allowNamespaceOperationAsync [%s] on [%s]...", operation.toString(), namespaceName.toString()));
        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            permissionFuture.complete(false);
            return permissionFuture;
        }

        Verifier verifier = res.get();

        Optional<NamespaceOperation> operationName = Stream.of(NamespaceOperation.values()).filter(e -> e == operation).findFirst();
        if (operationName.isPresent()) {
            verifier.add_fact(fact("namespace",
                    Arrays.asList(s("ambient"), string(namespaceName.getTenant()), string(namespaceName.getLocalName()))));

            // NamespaceOperation CREATE_TOPIC returns operation "create_topic"
            verifier.add_fact(fact("namespace_operation",
                    Arrays.asList(s("ambient"), string(namespaceName.getTenant()), string(namespaceName.getLocalName()), s(operationName.get().toString().toLowerCase()))));

            verifier.add_rule(constrained_rule("right",
                    Arrays.asList(s("authority"), var(0), var(1), var(2)),
                    Arrays.asList(
                            pred("right", Arrays.asList(s("authority"), s("admin"))),
                            pred("namespace_operation", Arrays.asList(s("ambient"), var(0), var(1), var(2)))
                    ),
                    Arrays.asList(new com.clevercloud.biscuit.token.builder.constraints.SymbolConstraint.InSet(2, new HashSet<>(Arrays.asList(
                            "create_topic",
                            "get_topic",
                            "get_topics",
                            "delete_topic",
                            "add_bundle",
                            "delete_bundle",
                            "get_bundle",
                            //"get_permission",
                            //"grant_permission",
                            //"revoke_permission",
                            "clear_backlog",
                            "unsubscribe"
                    ))))
            ));

            // NamespaceOperation CREATE_TOPIC returns operation "create_topic"
            verifier.add_caveat(new Caveat(Arrays.asList(
                    rule("check_right", Arrays.asList(),
                            Arrays.asList(
                                    pred("right", Arrays.asList(s("authority"), string(namespaceName.getTenant()), string(namespaceName.getLocalName()), s(operationName.get().toString().toLowerCase())))
                            )
                    )
            )));
        } else {
            throw new IllegalStateException(String.format("allowNamespacePolicyOperationAsync [%s] is not implemented.", operation.toString()));
        }

        log.info(verifier.print_world());
        Either verifierResult = verifier.verify();
        if (verifierResult.isLeft()) {
            log.error("verifier failure: {}", verifierResult.getLeft());
        } else {
            log.debug(String.format("allowNamespaceOperationAsync [%s] on [%s] authorized", operation.toString(), namespaceName.toString()));
        }

        permissionFuture.complete(verifierResult.isRight());

        return permissionFuture.thenCompose(isAuthorized -> {
            if (isAuthorized) {
                return CompletableFuture.completedFuture(true);
            } else {
                return isSuperUser(role, conf);
            }
        });
    }

    @Override
    public CompletableFuture<Boolean> allowNamespacePolicyOperationAsync(NamespaceName namespaceName, PolicyName policy, PolicyOperation operation, String originalRole, String role, AuthenticationDataSource authData) {
        if (!role.startsWith("biscuit:")) {
            return defaultProvider.allowNamespacePolicyOperationAsync(namespaceName, policy, operation, originalRole, role, authData);
        }

        log.debug(String.format("allowNamespacePolicyOperationAsync [%s]:[%s] on [%s]...", policy.toString(), operation.toString(), namespaceName.toString()));
        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            permissionFuture.complete(false);
            return permissionFuture;
        }

        Verifier verifier = res.get();
        Optional<PolicyName> policyName = Stream.of(PolicyName.values()).filter(e -> e == policy).findFirst();

        if (policyName.isPresent()) {
            verifier.add_fact(fact("namespace",
                    Arrays.asList(s("ambient"), string(namespaceName.getTenant()), string(namespaceName.getLocalName()))));

            // PolicyName OFFLOAD, operation READ returns operation "offload_read"
            verifier.add_fact(fact("namespace_operation",
                    Arrays.asList(s("ambient"), string(namespaceName.getTenant()), string(namespaceName.getLocalName()), s(policyName.get().toString().toLowerCase() + "_" + operation.toString().toLowerCase()))));

            verifier.add_rule(constrained_rule("right",
                    Arrays.asList(s("authority"), var(0), var(1), var(2)),
                    Arrays.asList(
                            pred("right", Arrays.asList(s("authority"), s("admin"))),
                            pred("namespace_operation", Arrays.asList(s("ambient"), var(0), var(1), var(2)))
                    ),
                    Arrays.asList(new com.clevercloud.biscuit.token.builder.constraints.SymbolConstraint.InSet(2, new HashSet<>(Arrays.asList(
                            "all_read",
                            //"all_write",
                            //"anty_affinity_write",
                            "anty_affinity_read",
                            "backlog_read",
                            "backlog_write",
                            "compaction_read",
                            "compaction_write",
                            "delayed_delivery_read",
                            "delayed_delivery_write",
                            "deduplication_read",
                            "deduplication_write",
                            "max_consumers_read",
                            "max_consumers_write",
                            "max_producers_read",
                            "max_producers_write",
                            "max_unacked_read",
                            "max_unacked_write",
                            "offload_read",
                            //"offload_write",
                            "persistence_read",
                            "persistence_write",
                            "rate_write",
                            "rate_read",
                            "retention_read",
                            "retention_write",
                            "replication_read",
                            //"replication_write",
                            "replication_rate_read",
                            //"replication_rate_write",
                            "schema_compatibility_strategy_read",
                            "schema_compatibility_strategy_write",
                            "subscription_auth_mode_read",
                            "subscription_auth_mode_write",
                            "encryption_read",
                            "encryption_write",
                            "ttl_read",
                            "ttl_write"
                    )))))
            );

            // PolicyName OFFLOAD, operation READ returns operation "offload_read"
            verifier.add_caveat(new Caveat(Arrays.asList(
                    rule("check_right",
                            Arrays.asList(),
                            Arrays.asList(
                                    pred("right", Arrays.asList(s("authority"), string(namespaceName.getTenant()), string(namespaceName.getLocalName()), s(policyName.get().toString().toLowerCase() + "_" + operation.toString().toLowerCase())))
                            )
                    )
            )));
        } else {
            throw new IllegalStateException(String.format("allowNamespacePolicyOperationAsync [%s] is not implemented.", operation.toString()));
        }

        log.info(verifier.print_world());

        Either verifierResult = verifier.verify();
        if (verifierResult.isLeft()) {
            log.error("verifier failure: {}", verifierResult.getLeft());
        } else {
            log.debug(String.format("allowNamespacePolicyOperationAsync [%s]:[%s] on [%s] authorized.", policy.toString(), operation.toString(), namespaceName.toString()));
        }

        permissionFuture.complete(verifierResult.isRight());

        return permissionFuture.thenCompose(isAuthorized -> {
            if (isAuthorized) {
                return CompletableFuture.completedFuture(true);
            } else {
                return isSuperUser(role, conf);
            }
        });
    }

    @Override
    public CompletableFuture<Boolean> allowTopicOperationAsync(TopicName topicName, String originalRole, String role,
                                                               TopicOperation operation,
                                                               AuthenticationDataSource authData) {
        CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

        Either<Error, Verifier> res = verifierFromBiscuit(role);
        if (res.isLeft()) {
            permissionFuture.complete(false);
            return permissionFuture;
        }

        Verifier verifier = res.get();

        verifier.add_fact(fact("topic",
                Arrays.asList(s("ambient"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()))));

        verifier.add_fact(fact("topic_operation",
                Arrays.asList(s("ambient"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), s(operation.toString().toLowerCase()))));

        // topic_operation $3 must be lookup
        verifier.add_rule(constrained_rule("right",
                Arrays.asList(s("authority"), var(0), var(1), var(2), var(3)),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("admin"))),
                        pred("topic_operation", Arrays.asList(s("ambient"), var(0), var(1), var(2), var(3)))
                ),
                Arrays.asList(new com.clevercloud.biscuit.token.builder.constraints.SymbolConstraint.InSet(3, new HashSet<>(Arrays.asList(
                        "lookup",
                        "produce",
                        "consume",
                        "compact",
                        "expire_messages",
                        "offload",
                        "peek_messages",
                        "reset_cursor",
                        "skip",
                        "terminate",
                        //"unload",
                        //"grant_permission",
                        //"get_permission",
                        //"revoke_permission",
                        //"add_bundle_range",
                        //"get_bundle_range",
                        //"delete_bundle_range",
                        "subscribe",
                        "get_subscriptions",
                        "unsubscribe",
                        "get_stats",
                        "skip_messages"
                ))))
        ));

        log.debug(verifier.print_world());

        Either verifierResult = verifier.verify();
        if (verifierResult.isLeft()) {
            log.error("verifier failure: {}", verifierResult.getLeft());
        } else {
            log.debug(String.format("allowTopicOperationAsync [%s] on [%s] authorized.", operation.toString(), topicName.toString()));
        }
        permissionFuture.complete(verifierResult.isRight());

        return permissionFuture.thenCompose(isAuthorized -> {
            if (isAuthorized) {
                return CompletableFuture.completedFuture(true);
            } else {
                return isSuperUser(role, conf);
            }
        });
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
