package com.example.gateway.apis;

import org.springframework.stereotype.Component;

@Component
public class ProductApiConfig extends BaseApiConfig {

    @Override
    public String getServiceName() {
        return "product-service";
    }

    @Override
    public String getServiceUrl() {
        return isDockerProfile() ? "http://product-service:8081" : "http://localhost:8081";
    }

    @Override
    public String getCircuitBreakerName() {
        return "product-cb";
    }

    @Override
    public String getFallbackUri() {
        return "forward:/fallback/product";
    }

    @Override
    public String getDirectPath() {
        return "/products/**";
    }

    @Override
    public String getPrefixedPath() {
        return "/product-service/**";
    }

    @Override
    public String getRewritePath() {
        return "/product-service/(?<segment>.*)";
    }

    @Override
    public String getRewriteReplacement() {
        return "/${segment}";
    }
}
