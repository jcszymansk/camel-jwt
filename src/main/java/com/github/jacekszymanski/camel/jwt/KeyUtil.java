package com.github.jacekszymanski.camel.jwt;

import org.apache.camel.CamelContext;
import org.apache.camel.Exchange;
import org.apache.camel.support.ResourceHelper;
import org.apache.camel.util.IOHelper;
import org.jose4j.keys.HmacKey;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.util.Base64;

public class KeyUtil {
  public static Key resolveKey(final JwtEndpoint endpoint, final Exchange exchange) throws IOException {
    final CamelContext ctx = endpoint.getCamelContext();

    // a key *must* be provided as a resource path, providing bytes/whatever in a header or uri is
    // not supported (it's a security nightmare)
    final String privateKeyLocation =
        exchange.getProperty(JwtConstants.JWT_PRIVATE_KEY_LOCATION, endpoint.getPrivateKeyLocation(), String.class);

    if (privateKeyLocation == null) {
      if (!endpoint.getAlgorithm().equals(JwtAlgorithm.none)) {
        throw new IllegalArgumentException("No key location provided");
      }

      return null;
    }

    // TODO: cache the key
    final String keyBase64 =
        IOHelper.loadText(ResourceHelper.resolveMandatoryResourceAsInputStream(ctx, privateKeyLocation));

    final byte[] keyBytes = Base64.getDecoder().decode(keyBase64);

    return new HmacKey(keyBytes);
  }
}
