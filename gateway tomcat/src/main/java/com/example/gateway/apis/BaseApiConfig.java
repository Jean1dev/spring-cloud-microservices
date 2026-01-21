package com.example.gateway.apis;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.server.mvc.filter.CircuitBreakerFilterFunctions;
import org.springframework.cloud.gateway.server.mvc.filter.FilterFunctions;
import org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

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

    public RouterFunction<ServerResponse> buildDirectRoute() {
        return GatewayRouterFunctions.route(getDirectPath())
            .filter(CircuitBreakerFilterFunctions.circuitBreaker(getCircuitBreakerName(), getFallbackUri()))
            .filter(FilterFunctions.uri(getServiceUrl()))
            .GET(req -> ServerResponse.ok().build())
            .POST(req -> ServerResponse.ok().build())
            .PUT(req -> ServerResponse.ok().build())
            .DELETE(req -> ServerResponse.ok().build())
            .build();
    }

    public RouterFunction<ServerResponse> buildPrefixedRoute() {
        return GatewayRouterFunctions.route(getPrefixedPath())
            .filter(FilterFunctions.rewritePath(getRewritePath(), getRewriteReplacement()))
            .filter(CircuitBreakerFilterFunctions.circuitBreaker(getCircuitBreakerName(), getFallbackUri()))
            .filter(FilterFunctions.uri(getServiceUrl()))
            .GET(req -> ServerResponse.ok().build())
            .POST(req -> ServerResponse.ok().build())
            .PUT(req -> ServerResponse.ok().build())
            .DELETE(req -> ServerResponse.ok().build())
            .build();
    }
}
