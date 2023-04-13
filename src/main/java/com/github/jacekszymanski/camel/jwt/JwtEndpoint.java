package com.github.jacekszymanski.camel.jwt;

import lombok.Getter;
import lombok.Setter;
import org.apache.camel.Category;
import org.apache.camel.Consumer;
import org.apache.camel.Processor;
import org.apache.camel.Producer;
import org.apache.camel.support.DefaultEndpoint;
import org.apache.camel.spi.Metadata;
import org.apache.camel.spi.UriEndpoint;
import org.apache.camel.spi.UriParam;
import org.apache.camel.spi.UriPath;
import org.apache.camel.support.ResourceHelper;

import java.util.concurrent.ExecutorService;

/**
 * Encode and sign or verify and decode JWT tokens
 *
 */
@UriEndpoint(firstVersion = "1.0-SNAPSHOT",
    scheme = "jwt",
    title = "Jwt",
    syntax = "jwt:algorithm:operation",
    producerOnly = true,
    category = {Category.SECURITY})
public class JwtEndpoint extends DefaultEndpoint {
  @UriPath @Metadata(required = true, description = "Algorithm to use for signing/verifying JWT tokens.\n" +
      "Supported algorithms are: HS256 and none (the processor will throw and exception if none is specified" +
      "and the option reallyWantNone is not set to true).\n")
  @Getter @Setter
  private JwtAlgorithm algorithm;

  @UriPath @Metadata(required = true, description = "Operation: Create or Decode," +
      "create will sign and encode a JWT token, decode will verify and decode a JWT token.\n" +
      "\n" +
      "Claims, unless otherwise specified are taken from/put into the message body.\n")
  @Getter @Setter
  private JwtOperation operation;

  @UriParam(defaultValue = "false",
      description = "If set to true, the processor will allow the use of the none algorithm.\n" +
          "This is for testing purposes only as it does not provide any security.\n")
  @Getter @Setter
  private boolean reallyWantNone = false;

  @UriParam(description = "Location of the secret key to sign tokens.")
  @Getter
  private String privateKeyLocation;

  @UriParam(description = "Name of the header (or, if starting with %, exchange property) containing " +
      "the JWT payload.")
  @Getter @Setter
  private String source;

  @UriParam(description = "Name of the header (or, if starting with %, exchange property) to put " +
      "the signed JWT token/decoded JWT payload.")
  @Getter @Setter
  private String target;

  @UriParam(defaultValue = "false",
      description = "If set to true, the processor will retain the source in the header/property. " +
          "(Body is always retained.)\n")
  @Getter @Setter
  private boolean retainSource = false;

  public JwtEndpoint() {
  }

  public JwtEndpoint(String uri, JwtComponent component) {
    super(uri, component);
  }

  public Producer createProducer() throws Exception {
    if (algorithm == JwtAlgorithm.none && !reallyWantNone) {
      throw new IllegalArgumentException("Algorithm none is not allowed, set reallyWantNone to true to allow it.");
    }
    return new JwtProducer(this);
  }

  public Consumer createConsumer(Processor processor) throws Exception {
    throw new UnsupportedOperationException("Consumer not supported");
  }

  public ExecutorService createExecutor() {
    // TODO: Delete me when you implemented your custom component
    return getCamelContext().getExecutorServiceManager().newSingleThreadExecutor(this, "JwtConsumer");
  }

  public void setPrivateKeyLocation(final String privateKeyLocation) {
    // check that this is a resource path, refuse if it's not for fear that the user has supplied a key
    // TODO: better check that the resource is a local one
    if (!isValidUri(privateKeyLocation)) {
      throw new IllegalArgumentException("Secret key location must be a non-http resource path, not a key");
    }
    this.privateKeyLocation = privateKeyLocation;
  }

  private static boolean isValidUri(final String uri) {
    return ResourceHelper.isClasspathUri(uri) ||
        (ResourceHelper.hasScheme(uri) && !ResourceHelper.isHttpUri(uri));
  }
}
