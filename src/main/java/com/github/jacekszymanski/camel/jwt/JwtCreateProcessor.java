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

    putToken(endpoint, exchange, signature.getCompactSerialization());

    // remove source only after the exchange is processed, so that in case of an error
    // it is still available for debugging
    final String sourceLocation = endpoint.getSource();
    if (sourceLocation != null && !endpoint.isRetainSource()) {
      removeSource(sourceLocation, exchange);
    }

  }

  private static void putToken(final JwtEndpoint endpoint, final Exchange exchange, final String token) {
    final String targetLocation = endpoint.getTarget();

    if (targetLocation == null) {
      exchange.getIn().setBody(token);
    } else if (targetLocation.startsWith("%")) {
      exchange.setProperty(targetLocation.substring(1), token);
    } else {
      exchange.getIn().setHeader(targetLocation, token);
    }
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

  private static void removeSource(final String sourceLocation, final Exchange exchange) {
    if (sourceLocation.startsWith("%")) {
      exchange.removeProperty(sourceLocation.substring(1));
    } else {
      exchange.getIn().removeHeader(sourceLocation);
    }
  }

}
