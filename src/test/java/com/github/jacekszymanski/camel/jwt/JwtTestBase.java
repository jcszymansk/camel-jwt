package com.github.jacekszymanski.camel.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.support.ResourceHelper;
import org.apache.camel.test.junit5.CamelTestSupport;
import org.apache.camel.util.IOHelper;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collections;
import java.util.Map;

public class JwtTestBase extends CamelTestSupport {

  private static final String UNSIGNED = "classpath:unsigned.txt";

  protected String unsignedBody;
  protected Map<String, Object> unsignedMap;
  protected MockEndpoint mockResult;

  @BeforeEach
  public void setUpX() throws Exception {
    super.setUp();
    unsignedBody = IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, UNSIGNED));
    unsignedMap = Collections.unmodifiableMap(new ObjectMapper().readValue(unsignedBody, Map.class));
    mockResult = getMockEndpoint("mock:result");
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
