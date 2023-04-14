package com.github.jacekszymanski.camel.jwt;

import lombok.RequiredArgsConstructor;
import org.apache.camel.Endpoint;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

@RequiredArgsConstructor
public class JwtDecodeProcessor implements Processor {

  private final JwtEndpoint endpoint;

  @Override
  public void process(Exchange exchange) throws Exception {
    final String token = getToken(endpoint, exchange);

    final JwtAlgorithm algorithm = endpoint.getAlgorithm();

    final JwtConsumerBuilder jwtConsumerBuilder = new JwtConsumerBuilder()
        .setVerificationKey(KeyUtil.resolveKey(endpoint, exchange))
        .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, algorithm.getIdentifier())
        ;

    if (endpoint.isReallyWantNone()) {
      jwtConsumerBuilder.setDisableRequireSignature();
    }

    final JwtConsumer jwtConsumer = jwtConsumerBuilder.build();

    putClaims(endpoint, exchange, jwtConsumer.processToClaims(token).toJson());

    if (endpoint.getSource() != null && !endpoint.isRetainSource()) {
      removeSource(endpoint.getSource(), exchange);
    }
  }

  private static String getToken(final JwtEndpoint endpoint, final Exchange exchange) {
    final String sourceLocation = endpoint.getSource();

    if (sourceLocation == null) {
      return exchange.getIn().getBody(String.class);
    } else if (sourceLocation.startsWith("%")) {
      return exchange.getProperty(sourceLocation.substring(1), String.class);
    } else {
      return exchange.getIn().getHeader(sourceLocation, String.class);
    }
  }

  private static void putClaims(final JwtEndpoint endpoint, final Exchange exchange, final String claims) {
    final String targetLocation = endpoint.getTarget();

    if (targetLocation == null) {
      exchange.getIn().setBody(claims);
    } else if (targetLocation.startsWith("%")) {
      exchange.setProperty(targetLocation.substring(1), claims);
    } else {
      exchange.getIn().setHeader(targetLocation, claims);
    }
  }

  // TODO refactor with JwtCreateProcessor
  private static void removeSource(final String sourceLocation, final Exchange exchange) {
    if (sourceLocation.startsWith("~")) {
      exchange.removeProperty(sourceLocation.substring(1));
    } else {
      exchange.getIn().removeHeader(sourceLocation);
    }
  }

}
