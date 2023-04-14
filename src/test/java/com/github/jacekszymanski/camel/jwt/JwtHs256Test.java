package com.github.jacekszymanski.camel.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.support.ResourceHelper;
import org.apache.camel.test.junit5.CamelTestSupport;
import org.apache.camel.util.IOHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;

public class JwtHs256Test extends CamelTestSupport {
  private static final String UNSIGNED = "classpath:unsigned.txt";
  private static final String SIGNED_HS256 = "classpath:signed.hs256.txt";
  private static final String KEY_HS256 = "classpath:key.hs256.txt";

  private String unsignedBody;
  private String signedBody;
  private Map<String, Object> unsignedMap;
  private MockEndpoint mockResult;

  @BeforeEach
  public void setUp() throws Exception {
    super.setUp();
    unsignedBody = IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, UNSIGNED));
    signedBody =
        IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, SIGNED_HS256)).trim();
    unsignedMap = Collections.unmodifiableMap(new ObjectMapper().readValue(unsignedBody, Map.class));
    mockResult = getMockEndpoint("mock:result");
  }

  @Test
  public void testHs256Sign() throws Exception {
    final String JWT_URI = "jwt:HS256:Create?privateKeyLocation=" + KEY_HS256;

    mockResult.expectedBodiesReceived(signedBody);

    template.send("direct://test", exchange -> {
      exchange.getIn().setBody(unsignedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

  // TODO refactor with JwtNoneTest
  @Override
  protected RouteBuilder createRouteBuilder() throws Exception {
    return new RouteBuilder() {
      public void configure() {
        from("direct://test")
            .toD("${exchangeProperty.JWT_URI}")
            .log("Signed: ${body}")
            .to("mock:result");

      }
    };
  }


}
