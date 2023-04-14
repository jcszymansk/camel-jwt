package com.github.jacekszymanski.camel.jwt;

import lombok.RequiredArgsConstructor;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RequiredArgsConstructor
public class JwtDecodeProcessor implements Processor {

  private final JwtEndpoint endpoint;

  @Override
  public void process(Exchange exchange) throws Exception {
    final String token;

    if (endpoint.isDecodeFindToken()) {
      token = findToken(Util.getInput(endpoint, exchange));
    } else {
      token = Util.getInput(endpoint, exchange);
    }

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

  private static String findToken(final String input) {
    final Pattern jwtPattern = Pattern.compile("([A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*)");

    final Matcher matcher = jwtPattern.matcher(input);

    if (matcher.find()) {
      final String match = matcher.group(1);

      if (matcher.find()) {
        throw new IllegalArgumentException("Multiple JWT tokens found in input");
      } else {
        return match;
      }
    } else {
      throw new IllegalArgumentException("No JWT token found in input");
    }
  }
}
