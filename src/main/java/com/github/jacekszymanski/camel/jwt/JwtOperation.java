package com.github.jacekszymanski.camel.jwt;

import org.apache.camel.Endpoint;
import org.apache.camel.Processor;

public enum JwtOperation {

  /**
   * Create a signed JWT token
   */
  Create {
    public Processor getProcessor(Endpoint endpoint) {
      return new JwtCreateProcessor((JwtEndpoint) endpoint);
    }
  },

  /**
   * Verify and decode a signed JWT token
   */
  Decode {
    public Processor getProcessor(Endpoint endpoint) {
      return new JwtDecodeProcessor(endpoint);
    }
  }
  ;

  public abstract Processor getProcessor(Endpoint endpoint);

}
