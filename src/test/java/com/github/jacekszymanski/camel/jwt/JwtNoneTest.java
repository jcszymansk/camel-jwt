package com.github.jacekszymanski.camel.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.support.ResourceHelper;
import org.apache.camel.test.junit5.CamelTestSupport;
import org.apache.camel.util.IOHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;

public class JwtNoneTest extends CamelTestSupport {

  private static final String UNSIGNED = "classpath:unsigned.txt";
  private static final String SIGNED_NONE = "classpath:signed.none.txt";
  private String unsignedBody;
  private String signedBody;
  private Map<String, Object> unsignedMap;
  private MockEndpoint mockResult;

  @BeforeEach
  public void setUp() throws Exception {
    super.setUp();
    unsignedBody = IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, UNSIGNED));
    signedBody =
        IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, SIGNED_NONE)).trim();
    unsignedMap = Collections.unmodifiableMap(new ObjectMapper().readValue(unsignedBody, Map.class));
    mockResult = getMockEndpoint("mock:result");
  }

  @Test
  public void testNoneSign() throws Exception {
    final String JWT_URI = "jwt:none:Create?reallyWantNone=true";

    mockResult.expectedBodiesReceived(signedBody);

    template.send("direct://test", exchange -> {
      exchange.getIn().setBody(unsignedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

  @Test
  public void testNoneSignFromHeader() throws Exception {
    final String JWT_URI = "jwt:none:Create?reallyWantNone=true&source=JwtClaims";

    mockResult.expectedBodiesReceived(signedBody);

    template.send("direct://test", exchange -> {
      exchange.getIn().setHeader("JwtClaims", unsignedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

  @Test
  public void testNoneSignFromProperty() throws Exception {
    final String JWT_URI = "jwt:none:Create?reallyWantNone=true&source=.JwtClaims";

    mockResult.expectedBodiesReceived(signedBody);

    template.send("direct://test", exchange -> {
      exchange.setProperty("JwtClaims", unsignedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

  @Test
  public void testNoneSignToHeader() throws Exception {
    final String JWT_URI = "jwt:none:Create?reallyWantNone=true&target=JwtToken";

    mockResult.expectedHeaderReceived("JwtToken", signedBody);

    template.send("direct://test", exchange -> {
      exchange.getIn().setBody(unsignedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

  @Test
  public void testNoneSignToProperty() throws Exception {
    final String JWT_URI = "jwt:none:Create?reallyWantNone=true&target=.JwtToken";

    mockResult.expectedPropertyReceived("JwtToken", signedBody);

    template.send("direct://test", exchange -> {
      exchange.getIn().setBody(unsignedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

  // In >90% of cases I want to get rid of the source header as soon as I've used it
  // so why not make it the default behavior?
  @Test
  public void testNoneSignClearHeader() throws Exception {
    final String JWT_URI = "jwt:none:Create?reallyWantNone=true&source=JwtClaims";

    mockResult.expectedHeaderReceived("JwtClaims", null);

    template.send("direct://test", exchange -> {
      exchange.getIn().setHeader("JwtClaims", unsignedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

  // but I can still keep it if I want to
  @Test
  public void testNoneSignRetainSourceHeader() throws Exception {
    final String JWT_URI = "jwt:none:Create?reallyWantNone=true&source=JwtClaims&retainSource=true";

    mockResult.expectedHeaderReceived("JwtClaims", unsignedBody);

    template.send("direct://test", exchange -> {
      exchange.getIn().setHeader("JwtClaims", unsignedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

  @Test
  public void testNoneDecode() throws Exception {
    final String JWT_URI = "jwt:none:Decode?reallyWantNone=true";

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setBody(signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    final Map<String, Object> signedMap =
        new ObjectMapper().readValue(result.getIn().getBody(String.class), Map.class);

    Assertions.assertEquals(unsignedMap, signedMap);
  }

  @Test
  public void testNoneDecodeFromHeader() throws Exception {
    final String JWT_URI = "jwt:none:Decode?reallyWantNone=true&source=JwtToken";

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setHeader("JwtToken", signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    final Map<String, Object> signedMap =
        new ObjectMapper().readValue(result.getIn().getBody(String.class), Map.class);

    Assertions.assertEquals(unsignedMap, signedMap);
  }

  @Test
  public void testNoneDecodeFromProperty() throws Exception {
    final String JWT_URI = "jwt:none:Decode?reallyWantNone=true&source=.JwtToken";

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.setProperty("JwtToken", signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    final Map<String, Object> signedMap =
        new ObjectMapper().readValue(result.getIn().getBody(String.class), Map.class);

    Assertions.assertEquals(unsignedMap, signedMap);

  }

  @Test
  public void testNoneDecodeToHeader() throws Exception {
    final String JWT_URI = "jwt:none:Decode?reallyWantNone=true&target=JwtClaims";

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setBody(signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    final Map<String, Object> signedMap =
        new ObjectMapper().readValue(result.getIn().getHeader("JwtClaims", String.class), Map.class);

    Assertions.assertEquals(unsignedMap, signedMap);
  }

  @Test
  public void testNoneDecodeToProperty() throws Exception {
    final String JWT_URI = "jwt:none:Decode?reallyWantNone=true&target=.JwtClaims";

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setBody(signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    final Map<String, Object> signedMap =
        new ObjectMapper().readValue(result.getProperty("JwtClaims", String.class), Map.class);

    Assertions.assertEquals(unsignedMap, signedMap);
  }

  @Test
  public void testNoneDecodeClearHeader() throws Exception {
    final String JWT_URI = "jwt:none:Decode?reallyWantNone=true&source=JwtToken";

    mockResult.expectedHeaderReceived("JwtToken", null);

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setHeader("JwtToken", signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

  @Test
  public void testNodeDecodeRetainSourceHeader() throws Exception {
    final String JWT_URI = "jwt:none:Decode?reallyWantNone=true&source=JwtToken&retainSource=true";

    mockResult.expectedHeaderReceived("JwtToken", signedBody);

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setHeader("JwtToken", signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

  @Test
  public void testNoRetainWithoutExplicitSource() throws Exception {
    final String JWT_URI = "jwt:none:Decode?reallyWantNone=true&retainSource=true";

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setHeader("JwtToken", signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    Assertions.assertNotNull(result.getException(IllegalArgumentException.class));
  }

  @Override
  protected RouteBuilder createRouteBuilder() throws Exception {
    return new RouteBuilder() {
      public void configure() {
        from("direct://test")
            .toD("${exchangeProperty.JWT_URI}")
            .to("mock:result");

      }
    };
  }

}
