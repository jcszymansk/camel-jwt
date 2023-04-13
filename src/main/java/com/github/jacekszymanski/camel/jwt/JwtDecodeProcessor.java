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

    exchange.getIn().setBody(jwtConsumer.processToClaims(token).toJson());
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
}
