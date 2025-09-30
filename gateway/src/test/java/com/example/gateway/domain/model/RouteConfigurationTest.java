package com.example.gateway.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RouteConfigurationTest {

    @Test
    void shouldCreateRouteConfigurationWithBuilder() {
        RouteConfiguration config = RouteConfiguration.builder()
                .id("test-route")
                .path("/test/**")
                .uri("http://localhost:8080")
                .circuitBreakerName("test-cb")
                .fallbackUri("forward:/fallback/test")
                .build();

        assertThat(config.id()).isEqualTo("test-route");
        assertThat(config.path()).isEqualTo("/test/**");
        assertThat(config.uri()).isEqualTo("http://localhost:8080");
        assertThat(config.circuitBreakerName()).isEqualTo("test-cb");
        assertThat(config.fallbackUri()).isEqualTo("forward:/fallback/test");
    }

    @Test
    void shouldThrowExceptionWhenIdIsNull() {
        assertThatThrownBy(() -> RouteConfiguration.builder()
                .id(null)
                .path("/test/**")
                .uri("http://localhost:8080")
                .circuitBreakerName("test-cb")
                .fallbackUri("forward:/fallback/test")
                .build())
                .isInstanceOf(NullPointerException.class)
                .hasMessage("ID cannot be null");
    }

    @Test
    void shouldThrowExceptionWhenPathIsNull() {
        assertThatThrownBy(() -> RouteConfiguration.builder()
                .id("test-route")
                .path(null)
                .uri("http://localhost:8080")
                .circuitBreakerName("test-cb")
                .fallbackUri("forward:/fallback/test")
                .build())
                .isInstanceOf(NullPointerException.class)
                .hasMessage("Path cannot be null");
    }

    @Test
    void shouldHaveCorrectEquality() {
        RouteConfiguration config1 = RouteConfiguration.builder()
                .id("test-route")
                .path("/test/**")
                .uri("http://localhost:8080")
                .circuitBreakerName("test-cb")
                .fallbackUri("forward:/fallback/test")
                .build();

        RouteConfiguration config2 = RouteConfiguration.builder()
                .id("test-route")
                .path("/test/**")
                .uri("http://localhost:8080")
                .circuitBreakerName("test-cb")
                .fallbackUri("forward:/fallback/test")
                .build();

        assertThat(config1).isEqualTo(config2);
        assertThat(config1.hashCode()).isEqualTo(config2.hashCode());
    }
}
