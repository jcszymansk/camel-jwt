package com.github.jacekszymanski.camel.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.support.ResourceHelper;
import org.apache.camel.test.junit4.CamelTestSupport;
import org.apache.camel.util.IOHelper;
import org.assertj.core.api.Assertions;
import org.junit.Test;

import java.util.Map;

public class JwtNoneTest extends CamelTestSupport {

    private final EventBusHelper eventBusHelper = EventBusHelper.getInstance();

    private static final String UNSIGNED = "classpath:unsigned.txt";
    private static final String SIGNED_NONE = "classpath:signed.none.txt";

    @Test
    public void testNoneSign() throws Exception {
        final String unsignedBody =
            IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, UNSIGNED));
        final String signedBody =
            IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, SIGNED_NONE)).trim();

        final MockEndpoint mock = getMockEndpoint("mock:result");
        mock.expectedBodiesReceived(signedBody);

        template.sendBody("direct://test", unsignedBody);

        mock.assertIsSatisfied();
    }

    @Test
    public void testNoneVerify() throws Exception {
        final String signedBody =
            IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, SIGNED_NONE));
        final String unsignedBody =
            IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, UNSIGNED));

        final Map<String, Object> unsignedMap = new ObjectMapper().readValue(unsignedBody, Map.class);

        final MockEndpoint mock = getMockEndpoint("mock:result");

        final Exchange result = template.send("direct://testDecode", exchange -> {
            exchange.getIn().setBody(signedBody);
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
                  .to("jwt:none:Create?reallyWantNone=true")
                  .to("mock:result");

                from("direct://testDecode")
                  .to("jwt:none:Decode?reallyWantNone=true")
                  .to("mock:result");
            }
        };
    }

}
