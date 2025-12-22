package com.example.gateway.apis;

import org.springframework.stereotype.Component;

@Component
public class UserApiConfig extends BaseApiConfig {

    @Override
    public String getServiceName() {
        return "user-service";
    }

    @Override
    public String getServiceUrl() {
        return isDockerProfile() ? "http://user-service:8080" : "http://localhost:8080";
    }

    @Override
    public String getCircuitBreakerName() {
        return "user-cb";
    }

    @Override
    public String getFallbackUri() {
        return "forward:/fallback/user";
    }

    @Override
    public String getDirectPath() {
        return "/users/**";
    }

    @Override
    public String getPrefixedPath() {
        return "/user-service/**";
    }

    @Override
    public String getRewritePath() {
        return "/user-service/(?<segment>.*)";
    }

    @Override
    public String getRewriteReplacement() {
        return "/${segment}";
    }
}
