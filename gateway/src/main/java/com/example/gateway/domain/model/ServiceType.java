package com.example.gateway.domain.model;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum ServiceType {
    USER_SERVICE("user-service", "http://localhost:8080"),
    PRODUCT_SERVICE("product-service", "http://localhost:8081"),
    ORDER_SERVICE("order-service", "http://localhost:8082");

    private final String name;
    private final String defaultUrl;
    
    private static final Map<String, ServiceType> BY_NAME = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(ServiceType::name, Function.identity()));

    ServiceType(String name, String defaultUrl) {
        this.name = name;
        this.defaultUrl = defaultUrl;
    }

    public String name() {
        return name;
    }

    public String defaultUrl() {
        return defaultUrl;
    }

    public static ServiceType fromName(String name) {
        ServiceType type = BY_NAME.get(name);
        if (type == null) {
            throw new IllegalArgumentException("Unknown service type: " + name);
        }
        return type;
    }
    
    public String getFallbackPath() {
        return "/fallback/" + name.replace("-service", "");
    }
    
    public String getCircuitBreakerName() {
        return name + "-cb";
    }
    
    public String getDirectPath() {
        return switch (this) {
            case USER_SERVICE -> "/users/**";
            case PRODUCT_SERVICE -> "/products/**";
            case ORDER_SERVICE -> "/orders/**";
        };
    }
    
    public String getPrefixedPath() {
        return "/" + name + "/**";
    }
}
