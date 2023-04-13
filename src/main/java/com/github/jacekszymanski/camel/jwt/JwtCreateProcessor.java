package com.github.jacekszymanski.camel.jwt;

import lombok.RequiredArgsConstructor;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;

import java.util.Optional;

@RequiredArgsConstructor
public class JwtCreateProcessor implements Processor {

  private final JwtEndpoint endpoint;

  @Override
  public void process(final Exchange exchange) throws Exception {
    final JwtAlgorithm algorithm = endpoint.getAlgorithm();

    final JwtClaims claims = getClaims(endpoint, exchange);
    final JsonWebSignature signature = new JsonWebSignature();
    signature.setAlgorithmHeaderValue(endpoint.getAlgorithm().getIdentifier());
    if (endpoint.isReallyWantNone()) {
      signature.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
    }
    signature.setHeader("typ", "JWT");
    signature.setPayload(claims.toJson());
    signature.setKey(KeyUtil.resolveKey(endpoint, exchange));

    exchange.getIn().setBody(signature.getCompactSerialization());
  }

  private static JwtClaims getClaims(final JwtEndpoint endpoint, final Exchange exchange) throws InvalidJwtException {
    final String sourceLocation = endpoint.getSource();

    final String claims;

    if (sourceLocation == null) {
      claims = exchange.getIn().getBody(String.class);
    } else if (sourceLocation.startsWith("%")) {
      claims = exchange.getProperty(sourceLocation.substring(1), String.class);
    } else {
      claims = exchange.getIn().getHeader(sourceLocation, String.class);
    }

    if (claims == null) {
      throw new IllegalArgumentException("No claims provided");
    }

    return JwtClaims.parse(claims);
  }

}
