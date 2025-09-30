package com.example.gateway.apis;

import org.springframework.beans.factory.annotation.Value;

public abstract class BaseApiConfig {

    @Value("${spring.profiles.active:default}")
    protected String activeProfile;

    protected boolean isDockerProfile() {
        return "docker".equals(activeProfile);
    }

    public abstract String getServiceUrl();
    public abstract String getCircuitBreakerName();
    public abstract String getFallbackUri();
    public abstract String getDirectPath();
    public abstract String getPrefixedPath();
    public abstract String getRewritePath();
    public abstract String getRewriteReplacement();
}
