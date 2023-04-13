package com.github.jacekszymanski.camel.jwt;

import lombok.RequiredArgsConstructor;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

@RequiredArgsConstructor
public class JwtCreateProcessor implements Processor {

  private final JwtEndpoint endpoint;

  @Override
  public void process(final Exchange exchange) throws Exception {
    final JwtAlgorithm algorithm = endpoint.getAlgorithm();

    final JwtClaims claims = JwtClaims.parse(exchange.getIn().getBody(String.class));
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

}
