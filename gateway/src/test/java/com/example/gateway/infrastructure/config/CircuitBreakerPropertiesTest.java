package com.example.gateway.infrastructure.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CircuitBreakerPropertiesTest {

    @Test
    void shouldCreateValidCircuitBreakerConfig() {
        CircuitBreakerProperties.CircuitBreakerConfig config = 
                new CircuitBreakerProperties.CircuitBreakerConfig(50, 30, 10, 5);

        assertThat(config.failureRateThreshold()).isEqualTo(50);
        assertThat(config.waitDurationInOpenStateSeconds()).isEqualTo(30);
        assertThat(config.slidingWindowSize()).isEqualTo(10);
        assertThat(config.minimumNumberOfCalls()).isEqualTo(5);
    }

    @Test
    void shouldThrowExceptionForInvalidFailureRateThreshold() {
        assertThatThrownBy(() -> new CircuitBreakerProperties.CircuitBreakerConfig(0, 30, 10, 5))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Failure rate threshold must be between 1 and 100");

        assertThatThrownBy(() -> new CircuitBreakerProperties.CircuitBreakerConfig(101, 30, 10, 5))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Failure rate threshold must be between 1 and 100");
    }

    @Test
    void shouldThrowExceptionForInvalidWaitDuration() {
        assertThatThrownBy(() -> new CircuitBreakerProperties.CircuitBreakerConfig(50, 0, 10, 5))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Wait duration must be at least 1 second");
    }

    @Test
    void shouldThrowExceptionForInvalidSlidingWindowSize() {
        assertThatThrownBy(() -> new CircuitBreakerProperties.CircuitBreakerConfig(50, 30, 0, 5))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Sliding window size must be at least 1");
    }

    @Test
    void shouldThrowExceptionForInvalidMinimumNumberOfCalls() {
        assertThatThrownBy(() -> new CircuitBreakerProperties.CircuitBreakerConfig(50, 30, 10, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Minimum number of calls must be at least 1");
    }
}
