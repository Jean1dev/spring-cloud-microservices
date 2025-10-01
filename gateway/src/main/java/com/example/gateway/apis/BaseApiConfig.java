package com.example.gateway.apis;

import com.example.gateway.filters.LoggingGatewayFilterFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.builder.Buildable;
import org.springframework.cloud.gateway.route.builder.PredicateSpec;

import java.util.function.Function;

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
    public abstract String getServiceName();

    public Function<PredicateSpec, Buildable<Route>> buildDirectRoute(LoggingGatewayFilterFactory loggingFilterFactory) {
        return r -> r.path(getDirectPath())
            .filters(f -> f
                .filter(loggingFilterFactory.apply(config -> config.setTargetService(getServiceName())))
                .circuitBreaker(config -> config
                    .setName(getCircuitBreakerName())
                    .setFallbackUri(getFallbackUri())))
            .uri(getServiceUrl());
    }

    public Function<PredicateSpec, Buildable<Route>> buildPrefixedRoute(LoggingGatewayFilterFactory loggingFilterFactory) {
        return r -> r.path(getPrefixedPath())
            .filters(f -> f
                .filter(loggingFilterFactory.apply(config -> config.setTargetService(getServiceName())))
                .rewritePath(getRewritePath(), getRewriteReplacement())
                .circuitBreaker(config -> config
                    .setName(getCircuitBreakerName())
                    .setFallbackUri(getFallbackUri())))
            .uri(getServiceUrl());
    }
}
