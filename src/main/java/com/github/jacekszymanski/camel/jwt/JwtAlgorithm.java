package com.github.jacekszymanski.camel.jwt;

public enum JwtAlgorithm {
  /**
   * No signature, for testing purposes only
   */
  None,

  /**
   * HMAC using SHA-256 hash algorithm
   */
  HS256;
}
