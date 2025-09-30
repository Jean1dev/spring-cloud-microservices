package com.example.gateway.apis;

import org.springframework.stereotype.Component;

@Component
public class OrderApiConfig extends BaseApiConfig {

    @Override
    public String getServiceUrl() {
        return isDockerProfile() ? "http://order-service:8082" : "http://localhost:8082";
    }

    @Override
    public String getCircuitBreakerName() {
        return "order-cb";
    }

    @Override
    public String getFallbackUri() {
        return "forward:/fallback/order";
    }

    @Override
    public String getDirectPath() {
        return "/orders/**";
    }

    @Override
    public String getPrefixedPath() {
        return "/order-service/**";
    }

    @Override
    public String getRewritePath() {
        return "/order-service/(?<segment>.*)";
    }

    @Override
    public String getRewriteReplacement() {
        return "/${segment}";
    }
}
