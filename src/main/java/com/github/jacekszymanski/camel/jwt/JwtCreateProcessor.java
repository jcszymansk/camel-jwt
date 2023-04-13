package com.github.jacekszymanski.camel.jwt;

import org.apache.camel.Endpoint;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;

public class JwtCreateProcessor implements Processor {
  public JwtCreateProcessor(Endpoint endpoint) {
  }

  @Override
  public void process(Exchange exchange) throws Exception {
    throw new UnsupportedOperationException("Not implemented yet");
  }
}
