package com.example.gateway.infrastructure.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@ConfigurationProperties(prefix = "resilience4j.circuitbreaker")
@Validated
public class CircuitBreakerProperties {

    @NotNull
    @Valid
    private CircuitBreakerConfig defaultConfig = new CircuitBreakerConfig(50, 30, 10, 5);

    public CircuitBreakerConfig getDefaultConfig() {
        return defaultConfig;
    }

    public void setDefaultConfig(CircuitBreakerConfig defaultConfig) {
        this.defaultConfig = defaultConfig;
    }

    public record CircuitBreakerConfig(
        @Min(1) @Max(100) int failureRateThreshold,
        @Min(1) int waitDurationInOpenStateSeconds,
        @Min(1) int slidingWindowSize,
        @Min(1) int minimumNumberOfCalls
    ) {
        public CircuitBreakerConfig {
            if (failureRateThreshold < 1 || failureRateThreshold > 100) {
                throw new IllegalArgumentException("Failure rate threshold must be between 1 and 100");
            }
            if (waitDurationInOpenStateSeconds < 1) {
                throw new IllegalArgumentException("Wait duration must be at least 1 second");
            }
            if (slidingWindowSize < 1) {
                throw new IllegalArgumentException("Sliding window size must be at least 1");
            }
            if (minimumNumberOfCalls < 1) {
                throw new IllegalArgumentException("Minimum number of calls must be at least 1");
            }
        }
    }
}
