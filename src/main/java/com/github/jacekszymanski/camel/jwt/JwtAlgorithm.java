package com.github.jacekszymanski.camel.jwt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.jose4j.jws.AlgorithmIdentifiers;

@RequiredArgsConstructor
public enum JwtAlgorithm {
  /**
   * No signature, for testing purposes only
   */
  None(AlgorithmIdentifiers.NONE),

  /**
   * HMAC using SHA-256 hash algorithm
   */
  HS256(AlgorithmIdentifiers.HMAC_SHA256);

  @Getter
  private final String identifier;
}
