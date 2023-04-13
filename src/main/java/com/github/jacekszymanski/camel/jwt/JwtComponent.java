package com.github.jacekszymanski.camel.jwt;

import java.util.Map;

import org.apache.camel.Endpoint;

import org.apache.camel.support.DefaultComponent;

@org.apache.camel.spi.annotations.Component("jwt")
public class JwtComponent extends DefaultComponent {

    protected Endpoint createEndpoint(String uri, String remaining, Map<String, Object> parameters) throws Exception {
        Endpoint endpoint = new JwtEndpoint(uri, this);
        setProperties(endpoint, parameters);
        return endpoint;
    }
}
