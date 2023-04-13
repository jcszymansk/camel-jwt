package com.github.jacekszymanski.camel.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.support.ResourceHelper;
import org.apache.camel.test.junit4.CamelTestSupport;
import org.apache.camel.util.IOHelper;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.Map;

public class JwtNoneTest extends CamelTestSupport {

    private final EventBusHelper eventBusHelper = EventBusHelper.getInstance();

    private static final String UNSIGNED = "classpath:unsigned.txt";
    private static final String SIGNED_NONE = "classpath:signed.none.txt";
    private String unsignedBody;
    private String signedBody;
    private Map<String, Object> unsignedMap;
    private MockEndpoint mockResult;

    @Before
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
        final String JWT_URI = "jwt:none:Create?reallyWantNone=true&source=%JwtClaims";

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
    public void testNoneVerify() throws Exception {
        final String JWT_URI = "jwt:none:Decode?reallyWantNone=true";

        final Exchange result = template.send("direct://test", exchange -> {
            exchange.getIn().setBody(signedBody);
            exchange.setProperty("JWT_URI", JWT_URI);
        });

        final Map<String, Object> signedMap =
            new ObjectMapper().readValue(result.getIn().getBody(String.class), Map.class);

        Assertions.assertThat(signedMap).isEqualTo(unsignedMap);
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
