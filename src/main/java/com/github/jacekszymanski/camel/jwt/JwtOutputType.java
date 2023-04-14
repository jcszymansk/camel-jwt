package com.github.jacekszymanski.camel.jwt;

public enum JwtOutputType {
  /**
   * Output decoded token as a Map; uses Jackson to deserialize the token
   */
  Map,
  /**
   * Output decoded token as a JSON String
   */
  String;
}
