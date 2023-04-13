package com.github.jacekszymanski.camel.jwt;

public enum JwtOperation {

  /**
   * Create a signed JWT token
   */
  Create,

  /**
   * Verify and decode a signed JWT token
   */
  Decode;

}
