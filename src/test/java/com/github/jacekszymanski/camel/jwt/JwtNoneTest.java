package com.github.jacekszymanski.camel.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.support.ResourceHelper;
import org.apache.camel.util.IOHelper;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

public class JwtNoneTest extends JwtTestBase {

  private static final String SIGNED_NONE = "classpath:signed.none.txt";
  private String signedBody;

  @BeforeEach
  public void setUpX() throws Exception {
    super.setUpX();
    signedBody =
        IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, SIGNED_NONE)).trim();
  }

  @Test
  public void testNoneSign() throws Exception {
    final String JWT_URI = "jwt:none:Create?reallyWantNone=true";

    mockResult.expectedMessageCount(1);
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

    mockResult.expectedMessageCount(1);
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

    mockResult.expectedMessageCount(1);
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

    mockResult.expectedMessageCount(1);
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

    mockResult.expectedMessageCount(1);
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

    mockResult.expectedMessageCount(1);
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

    mockResult.expectedMessageCount(1);
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

    mockResult.expectedMessageCount(1);
    mockResult.expectedHeaderReceived("JwtToken", null);

    template.send("direct://test", exchange -> {
      exchange.getIn().setHeader("JwtToken", signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

  @Test
  public void testNodeDecodeRetainSourceHeader() throws Exception {
    final String JWT_URI = "jwt:none:Decode?reallyWantNone=true&source=JwtToken&retainSource=true";

    mockResult.expectedMessageCount(1);
    mockResult.expectedHeaderReceived("JwtToken", signedBody);

    template.send("direct://test", exchange -> {
      exchange.getIn().setHeader("JwtToken", signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

  @Test
  public void testNoneDecodePartOfHeader() throws Exception {
    final String JWT_URI = "jwt:none:Decode?reallyWantNone=true&source=Authorization&target=.JwtClaims";

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setHeader("Authorization", "Bearer " + signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    final Map<String, Object> signedMap =
        new ObjectMapper().readValue(result.getProperty("JwtClaims", String.class), Map.class);

    Assertions.assertEquals(unsignedMap, signedMap);

  }

  @Test
  public void testNoneRefusePartOfHeader() throws Exception {
    final String JWT_URI = "jwt:none:Decode?reallyWantNone=true&source=Authorization&target=.JwtClaims&decodeFindToken=false";

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setHeader("Authorization", "Bearer " + signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    Assertions.assertNotNull(result.getProperty(Exchange.EXCEPTION_CAUGHT, InvalidJwtException.class));
  }

  @Test
  public void testFindOnlySingleToken() throws Exception {
    final String JWT_URI = "jwt:none:Decode?reallyWantNone=true&source=Authorization&target=.JwtClaims";

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setHeader("Authorization", "Bearer " + signedBody + " SomethingElse XXX" + signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    Assertions.assertNotNull(result.getProperty(Exchange.EXCEPTION_CAUGHT, IllegalArgumentException.class));
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

  @Test
  public void testNoneDecodeToMap() throws Exception {
    final String JWT_URI = "jwt:none:Decode?reallyWantNone=true&outputType=Map";

    final Exchange result = template.send("direct://test", exchange -> {
      exchange.getIn().setBody(signedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    final Map<String, Object> signedMap = result.getIn().getBody(Map.class);

    Assertions.assertEquals(unsignedMap, signedMap);
  }


}
