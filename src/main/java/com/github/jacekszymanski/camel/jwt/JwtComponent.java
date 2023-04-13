package com.github.jacekszymanski.camel.jwt;

import java.util.Map;

import org.apache.camel.Endpoint;

import org.apache.camel.support.DefaultComponent;

@org.apache.camel.spi.annotations.Component("jwt")
public class JwtComponent extends DefaultComponent {

  protected Endpoint createEndpoint(String uri, String remaining, Map<String, Object> parameters) throws Exception {
    JwtEndpoint endpoint = new JwtEndpoint(uri, this);
    final String[] parts = remaining.split(":");
    if (parts.length != 2) {
      throw new IllegalArgumentException("Invalid endpoint uri: " + uri);
    }
    endpoint.setAlgorithm(JwtAlgorithm.valueOf(parts[0]));
    endpoint.setOperation(JwtOperation.valueOf(parts[1]));
    setProperties(endpoint, parameters);
    return endpoint;
  }
}
