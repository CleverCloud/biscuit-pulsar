package com.clevercloud.biscuitpulsar;

import com.clevercloud.biscuit.error.Error;
import com.clevercloud.biscuit.token.Biscuit;
import com.clevercloud.biscuit.token.Verifier;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import static com.clevercloud.biscuit.token.builder.Utils.*;
import static com.clevercloud.biscuit.token.builder.Utils.s;
import static io.vavr.API.Left;
import static io.vavr.API.Right;

public class AuthorizationProviderBiscuit implements AuthorizationProvider {
  private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationProviderBiscuit.class);

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

  private Predicate topicSubscriptionRight(TopicName topicName, String subscription, String right) {
    return pred("right", Arrays.asList(s("authority"), s("topic"),
        string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), s(right), string(subscription)));
  }

  public Either<Error, Verifier> verifierFromBiscuit(String role) {
    LOGGER.info("verifierFromBiscuit: got role: {}", role);
    Either<Error, Biscuit> deser = Biscuit.from_sealed(
      Base64.getDecoder().decode(role.substring("biscuit:".length())),
      AuthenticationProviderBiscuit.BISCUIT_SEALING_KEY.getBytes()
    );
    if(deser.isLeft()) {
      Error e = deser.getLeft();
      return Left(e);
    }

    Biscuit token = deser.get();
    LOGGER.info("will authorize with token:\n{}", token.print());

    Either<Error, Verifier> res = token.verify_sealed();
    if(res.isLeft()) {
      return res;
    }

    Verifier verifier = res.get();
    verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("lookup")),
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
            pred("subscription", Arrays.asList(s("ambient"),  var(0), var(1), var(2), var(3)))
        )));

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
    if(!role.startsWith("biscuit:")) {
      return defaultProvider.canProduceAsync(topicName, role, authenticationData);
    }

    CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();
    LOGGER.info("got role : {}", role);

    Either<Error, Verifier> res = verifierFromBiscuit(role);
    if(res.isLeft()) {
      LOGGER.error("could not create verifier");
      permissionFuture.complete(false);
    }

    LOGGER.info("created verifier");
    Verifier verifier = res.get();

    verifier.add_fact(topic(topicName));
    verifier.add_operation("produce");
    verifier.set_time();

    verifier.add_authority_caveat(rule("checked_produce_right", Arrays.asList(string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName())),
      Arrays.asList(
        topicRight(topicName, "produce")
      )));

    Either<Error, HashMap<String, HashMap<Long, Set<Fact>>>> verifierResult = verifier.verify();
    if(verifierResult.isLeft()) {
      LOGGER.error("produce verifier failure: {}", verifierResult.getLeft());
    } else {
      LOGGER.info("produce request authorized by biscuit token");
    }

    permissionFuture.complete(verifierResult.isRight());

    return permissionFuture;
  }

  @Override
  public CompletableFuture<Boolean> canConsumeAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData, String subscription) {
    if(!role.startsWith("biscuit:")) {
      return defaultProvider.canConsumeAsync(topicName, role, authenticationData, subscription);
    }

    CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

    Either<Error, Verifier> res = verifierFromBiscuit(role);
    if(res.isLeft()) {
      permissionFuture.complete(false);
    }

    Verifier verifier = res.get();

    verifier.add_fact(topic(topicName));
    verifier.add_operation("consume");
    verifier.add_fact(subscription(topicName, subscription));
    verifier.set_time();

    // add these rules because there are two ways to verify that we can consume: with a right defined on the topic
    // or one defined on the subscription
    verifier.add_rule(rule("can_consume", Arrays.asList(s("authority"), s("topic"), string(topicName.getTenant()), string(topicName.getNamespacePortion()),  string(topicName.getLocalName())),
        Arrays.asList(
            topicSubscriptionRight(topicName, subscription, "consume"))));

    verifier.add_rule(rule("can_consume", Arrays.asList(s("authority"), s("topic"), string(topicName.getTenant()), string(topicName.getNamespacePortion()),  string(topicName.getLocalName())),
        Arrays.asList(
            topicRight(topicName, "consume"))));

    verifier.add_authority_caveat(rule("checked_consume_right", Arrays.asList(s("topic"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName()), s("consume")),
        Arrays.asList(
            pred("can_consume", Arrays.asList(s("authority"), s("topic"), string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName())))
        )));

    Either<Error, HashMap<String, HashMap<Long, Set<Fact>>>> verifierResult = verifier.verify();
    if(verifierResult.isLeft()) {
      LOGGER.error("consume verifier failure: {}", verifierResult.getLeft());
    } else {
      LOGGER.info("consume request authorized by biscuit token");
    }

    permissionFuture.complete(verifierResult.isRight());

    return permissionFuture;
  }

  @Override
  public CompletableFuture<Boolean> canLookupAsync(TopicName topicName, String role, AuthenticationDataSource authenticationData) {
    if(!role.startsWith("biscuit:")) {
      return defaultProvider.canLookupAsync(topicName, role, authenticationData);
    }

    CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

    Either<Error, Verifier> res = verifierFromBiscuit(role);
    if(res.isLeft()) {
      permissionFuture.complete(false);
    }

    Verifier verifier = res.get();

    verifier.add_fact(topic(topicName));

    // add both operations because produce and consume rights imply lookup rights
    verifier.add_operation("produce");
    verifier.add_operation("consume");

    verifier.add_operation("lookup");
    verifier.set_time();

    verifier.add_authority_caveat(rule("checked_lookup_right", Arrays.asList(string(topicName.getTenant()), string(topicName.getNamespacePortion()), string(topicName.getLocalName())),
        Arrays.asList(
            topicRight(topicName, "lookup")
        )));

    Either<Error, HashMap<String, HashMap<Long, Set<Fact>>>> verifierResult = verifier.verify();
    if(verifierResult.isLeft()) {
      LOGGER.error("lookup verifier failure: {}", verifierResult.getLeft());
    } else {
      LOGGER.info("lookup authorized by biscuit token");
    }
    permissionFuture.complete(verifierResult.isRight());

    return permissionFuture;
  }

  @Override
  public CompletableFuture<Boolean> allowFunctionOpsAsync(NamespaceName namespaceName, String role, AuthenticationDataSource authenticationData) {
    if(!role.startsWith("biscuit:")) {
      return defaultProvider.allowFunctionOpsAsync(namespaceName, role, authenticationData);
    }

    CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

    Either<Error, Verifier> res = verifierFromBiscuit(role);
    if(res.isLeft()) {
      permissionFuture.complete(false);
    }

    Verifier verifier = res.get();

    verifier.add_fact(fact("namespace", Arrays.asList(s("ambient"), string(namespaceName.getTenant()), string(namespaceName.getLocalName()))));
    verifier.add_operation("functions");
    verifier.set_time();

    verifier.add_authority_caveat(rule("checked_allowfunction_right", Arrays.asList(string(namespaceName.getTenant()), string(namespaceName.getLocalName())),
      Arrays.asList(
        pred("right", Arrays.asList(s("authority"), s("namespace"), string(namespaceName.getTenant()), string(namespaceName.getLocalName()), s("functions")))
      )));

    Either<Error, HashMap<String, HashMap<Long, Set<Fact>>>> verifierResult = verifier.verify();
    permissionFuture.complete(verifierResult.isRight());

    return permissionFuture;
  }


  @Override
  public CompletableFuture<Boolean> isSuperUser(String role, ServiceConfiguration serviceConfiguration) {
    if(!role.startsWith("biscuit:")) {
      return defaultProvider.isSuperUser(role, serviceConfiguration);
    }

    LOGGER.info("BISCUIT: isSuperUser? got role: {}", role);
    CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();

    Either<Error, Verifier> res = verifierFromBiscuit(role);
    if(res.isLeft()) {
      permissionFuture.complete(false);
    }

    Verifier verifier = res.get();

    verifier.add_authority_caveat(rule("checked_issuperuser_right", Arrays.asList(s("admin")),
      Arrays.asList(
        pred("right", Arrays.asList(s("authority"), s("admin")))
      )));

    Either<Error, HashMap<String, HashMap<Long, Set<Fact>>>> verifierResult = verifier.verify();
    if(verifierResult.isLeft()) {
      LOGGER.error("verifier failure: {}", verifierResult.getLeft());
    } else {
      LOGGER.info("superuser authorized by biscuit token");
    }

    permissionFuture.complete(verifierResult.isRight());

    return permissionFuture;
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
