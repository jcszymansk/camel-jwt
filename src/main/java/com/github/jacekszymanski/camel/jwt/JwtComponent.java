package com.github.jacekszymanski.camel.jwt;

import java.util.Map;

import lombok.Getter;
import lombok.Setter;
import org.apache.camel.Endpoint;

import org.apache.camel.spi.Metadata;
import org.apache.camel.spi.annotations.Component;
import org.apache.camel.support.DefaultComponent;

@Component("jwt")
public class JwtComponent extends DefaultComponent {

  @Metadata(description = "The location of the private key file")
  @Getter
  private String privateKeyLocation;

  protected Endpoint createEndpoint(String uri, String remaining, Map<String, Object> parameters) throws Exception {
    JwtEndpoint endpoint = new JwtEndpoint(uri, this);

    if (privateKeyLocation != null) {
      endpoint.setPrivateKeyLocation(privateKeyLocation);
    }

    final String[] parts = remaining.split(":");
    if (parts.length != 2) {
      throw new IllegalArgumentException("Invalid endpoint uri: " + uri);
    }
    endpoint.setAlgorithm(JwtAlgorithm.valueOf(parts[0]));
    endpoint.setOperation(JwtOperation.valueOf(parts[1]));
    setProperties(endpoint, parameters);
    return endpoint;
  }

  public void setPrivateKeyLocation(String privateKeyLocation) {
    if (!Util.isValidUri(privateKeyLocation)) {
      throw new IllegalArgumentException("Invalid key location provided (must be a local resource)");
    }
    this.privateKeyLocation = privateKeyLocation;
  }
}
