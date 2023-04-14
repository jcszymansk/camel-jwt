package com.github.jacekszymanski.camel.jwt;

import lombok.RequiredArgsConstructor;
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
    final String token = Util.getInput(endpoint, exchange);

    final JwtAlgorithm algorithm = endpoint.getAlgorithm();

    final JwtConsumerBuilder jwtConsumerBuilder = new JwtConsumerBuilder()
        .setVerificationKey(Util.resolveKey(endpoint, exchange))
        .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, algorithm.getIdentifier())
        ;

    if (endpoint.isReallyWantNone()) {
      jwtConsumerBuilder.setDisableRequireSignature();
    }

    final JwtConsumer jwtConsumer = jwtConsumerBuilder.build();

    Util.putResult(endpoint, exchange, jwtConsumer.processToClaims(token).toJson());

    if (endpoint.getSource() != null && !endpoint.isRetainSource()) {
      Util.removeSource(endpoint.getSource(), exchange);
    }
  }

}
