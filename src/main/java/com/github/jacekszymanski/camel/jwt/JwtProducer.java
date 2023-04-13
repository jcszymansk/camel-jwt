package com.github.jacekszymanski.camel.jwt;

import org.apache.camel.Exchange;
import org.apache.camel.support.DefaultProducer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwtProducer extends DefaultProducer {
    private static final Logger LOG = LoggerFactory.getLogger(JwtProducer.class);
    private JwtEndpoint endpoint;

    public JwtProducer(JwtEndpoint endpoint) {
        super(endpoint);
        this.endpoint = endpoint;
    }

    public void process(Exchange exchange) throws Exception {
        System.out.println(exchange.getIn().getBody());
    }

}
