package com.github.jacekszymanski.camel.jwt;

import lombok.RequiredArgsConstructor;
import org.apache.camel.CamelContext;
import org.apache.camel.Endpoint;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.apache.camel.support.ResourceHelper;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.HmacKey;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;

@RequiredArgsConstructor
public class JwtCreateProcessor implements Processor {

  private final JwtEndpoint endpoint;

  @Override
  public void process(final Exchange exchange) throws Exception {
    final JwtAlgorithm algorithm = endpoint.getAlgorithm();

    final JwtClaims claims = JwtClaims.parse(exchange.getIn().getBody(String.class));
    final JsonWebSignature signature = new JsonWebSignature();
    signature.setAlgorithmHeaderValue(endpoint.getAlgorithm().getIdentifier());
    signature.setPayload(claims.toJson());
    signature.setKey(resolveKey(exchange));

    exchange.getIn().setBody(signature.getCompactSerialization());

  }

  public Key resolveKey(final Exchange exchange) throws IOException {
    final CamelContext ctx = endpoint.getCamelContext();

    // a key *must* be provided as a resource path, providing bytes/whatever in a header or uri is
    // not supported (it's a security nightmare)
    final String privateKeyLocation =
        exchange.getIn().getHeader(JwtConstants.JWT_PRIVATE_KEY_LOCATION, endpoint.getPrivateKeyLocation(), String.class);
    if (privateKeyLocation == null && !endpoint.getAlgorithm().equals(JwtAlgorithm.None)) {
      throw new IllegalArgumentException("No key location provided");
    }

    // TODO: cache the key
    try (InputStream keyInputStream = ResourceHelper.resolveMandatoryResourceAsInputStream(ctx, privateKeyLocation)) {
      final ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
      keyBytes.writeBytes(keyInputStream.readAllBytes());

      return new HmacKey(keyBytes.toByteArray());
    }
  }
}
