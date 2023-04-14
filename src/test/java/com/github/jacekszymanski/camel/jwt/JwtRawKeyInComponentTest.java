package com.github.jacekszymanski.camel.jwt;

import org.apache.camel.support.ResourceHelper;
import org.apache.camel.util.IOHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class JwtRawKeyInComponentTest extends JwtTestBase {

  private String signedBody;

  @Override
  @BeforeEach
  public void setUp() throws Exception {
    super.setUp();
  }

  @Test
  public void testAttemptPutRawKeyInComponent() throws Exception {
    final JwtComponent jwtComponent = new JwtComponent();

    final String rawKey = IOHelper.loadText(
        ResourceHelper.resolveMandatoryResourceAsInputStream(context, JwtHs256Test.KEY_HS256)).trim();

    Assertions.assertThrows(IllegalArgumentException.class,
        () -> jwtComponent.setPrivateKeyLocation(rawKey));
  }

}
