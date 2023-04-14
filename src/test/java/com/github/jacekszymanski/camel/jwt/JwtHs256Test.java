package com.github.jacekszymanski.camel.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.support.ResourceHelper;
import org.apache.camel.util.IOHelper;
import org.jose4j.jwt.consumer.InvalidJwtSignatureException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;

public class JwtHs256Test extends JwtTestBase {
  static final String SIGNED_HS256 = "classpath:signed.hs256.txt";
  private static final String SIGNED_WRONG_HS256 = "classpath:signed-wrong.hs256.txt";
  static final String KEY_HS256 = "classpath:key.hs256.txt";

  protected String signedBody;

  @BeforeEach
  public void setUp() throws Exception {
    super.setUp();
    signedBody =
        IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, SIGNED_HS256)).trim();
    unsignedMap = Collections.unmodifiableMap(new ObjectMapper().readValue(unsignedBody, Map.class));
    mockResult = getMockEndpoint("mock:result");
  }

  @Test
  public void testHs256Sign() throws Exception {
    final String JWT_URI = "jwt:HS256:Create?privateKeyLocation=" + KEY_HS256;

    mockResult.expectedMessageCount(1);
    mockResult.expectedBodiesReceived(signedBody);

    template.send("direct://test", exchange -> {
      exchange.getIn().setBody(unsignedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

  @Test
  public void testHs256Decode() throws Exception {
    final String JWT_URI = "jwt:HS256:Decode?privateKeyLocation=" + KEY_HS256;

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setBody(signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    final Map<String, Object> signedMap =
        new ObjectMapper().readValue(result.getIn().getBody(String.class), Map.class);

    Assertions.assertEquals(unsignedMap, signedMap);
  }

  @Test
  public void testHs256DecodeWrongSig() throws Exception {
    final String JWT_URI = "jwt:HS256:Decode?privateKeyLocation=" + KEY_HS256;

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setBody(
          IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, SIGNED_WRONG_HS256)));
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    Assertions.assertNotNull(result.getProperty(Exchange.EXCEPTION_CAUGHT, InvalidJwtSignatureException.class));
  }

  @Test
  public void testHs256SignKeyInProperty() throws Exception {
    final String JWT_URI = "jwt:HS256:Create";

    mockResult.expectedMessageCount(1);
    mockResult.expectedBodiesReceived(signedBody);

    template.send("direct://test", exchange -> {
      exchange.getIn().setBody(unsignedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
      exchange.setProperty(JwtConstants.JWT_PRIVATE_KEY_LOCATION, KEY_HS256);
    });

    mockResult.assertIsSatisfied();
  }

  @Test
  public void testHs256ExceptionOnRawKeyInProperty() throws Exception {
    final String JWT_URI = "jwt:HS256:Create";

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setBody(unsignedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
      exchange.setProperty(JwtConstants.JWT_PRIVATE_KEY_LOCATION,
          IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, KEY_HS256)));
    });

    Assertions.assertNotNull(result.getProperty(Exchange.EXCEPTION_CAUGHT, IllegalArgumentException.class));
  }

}
