package com.example.gateway.domain.model;

import java.util.Objects;

public record RouteConfiguration(
    String id,
    String path,
    String uri,
    String circuitBreakerName,
    String fallbackUri
) {
    
    public RouteConfiguration {
        Objects.requireNonNull(id, "ID cannot be null");
        Objects.requireNonNull(path, "Path cannot be null");
        Objects.requireNonNull(uri, "URI cannot be null");
        Objects.requireNonNull(circuitBreakerName, "Circuit breaker name cannot be null");
        Objects.requireNonNull(fallbackUri, "Fallback URI cannot be null");
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String id;
        private String path;
        private String uri;
        private String circuitBreakerName;
        private String fallbackUri;

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder path(String path) {
            this.path = path;
            return this;
        }

        public Builder uri(String uri) {
            this.uri = uri;
            return this;
        }

        public Builder circuitBreakerName(String circuitBreakerName) {
            this.circuitBreakerName = circuitBreakerName;
            return this;
        }

        public Builder fallbackUri(String fallbackUri) {
            this.fallbackUri = fallbackUri;
            return this;
        }

        public RouteConfiguration build() {
            return new RouteConfiguration(id, path, uri, circuitBreakerName, fallbackUri);
        }
    }
}
