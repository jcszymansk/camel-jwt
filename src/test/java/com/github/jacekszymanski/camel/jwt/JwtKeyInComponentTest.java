package com.github.jacekszymanski.camel.jwt;

import org.apache.camel.support.ResourceHelper;
import org.apache.camel.util.IOHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.github.jacekszymanski.camel.jwt.JwtHs256Test.SIGNED_HS256;

public class JwtKeyInComponentTest extends JwtTestBase {

  private String signedBody;

  @Override
  @BeforeEach
  public void setUpX() throws Exception {
    super.setUpX();

    final JwtComponent jwtComponent = new JwtComponent();
    jwtComponent.setPrivateKeyLocation(JwtHs256Test.KEY_HS256);

    context.addComponent("jwt", jwtComponent);

    signedBody =
        IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(context, SIGNED_HS256)).trim();
  }

  @Test
  public void testHs256Sign() throws Exception {
    final String JWT_URI = "jwt:HS256:Create";

    mockResult.expectedMessageCount(1);
    mockResult.expectedBodiesReceived(signedBody);

    template.send("direct://test", exchange -> {
      exchange.getIn().setBody(unsignedBody);
      exchange.setProperty("JWT_URI", JWT_URI);
    });

    mockResult.assertIsSatisfied();
  }

}
