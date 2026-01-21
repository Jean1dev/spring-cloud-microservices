package com.example.gateway.filters;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class LoggingGatewayFilterFactoryTest {

    @Test
    void shouldCreateFilterWithConfig() {
        LoggingGatewayFilterFactory factory = new LoggingGatewayFilterFactory();
        
        LoggingGatewayFilterFactory.Config config = new LoggingGatewayFilterFactory.Config();
        config.setTargetService("test-service");
        
        GatewayFilter filter = factory.apply(config);
        
        assertNotNull(filter);
    }

    @Test
    void shouldProcessRequestAndResponse() {
        LoggingGatewayFilterFactory factory = new LoggingGatewayFilterFactory();
        
        LoggingGatewayFilterFactory.Config config = new LoggingGatewayFilterFactory.Config();
        config.setTargetService("test-service");
        
        GatewayFilter filter = factory.apply(config);
        
        MockServerHttpRequest request = MockServerHttpRequest
            .get("http://localhost:8083/test")
            .build();
        
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        
        StepVerifier.create(filter.filter(exchange, exchange2 -> Mono.empty()))
            .verifyComplete();
    }

    @Test
    void shouldHaveCorrectConfigClass() {
        LoggingGatewayFilterFactory factory = new LoggingGatewayFilterFactory();
        
        assertEquals(LoggingGatewayFilterFactory.Config.class, factory.getConfigClass());
    }
}
