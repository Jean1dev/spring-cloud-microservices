package com.example.gateway.application.service;

import com.example.gateway.domain.model.RouteConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

class RouteConfigurationServiceTest {

    private RouteConfigurationService routeConfigurationService;

    @BeforeEach
    void setUp() {
        routeConfigurationService = new RouteConfigurationService();
    }

    @Test
    void shouldReturnAllRouteConfigurations() {
        StepVerifier.create(routeConfigurationService.getAllRouteConfigurations())
                .expectNextCount(6)
                .verifyComplete();
    }

    @Test
    void shouldReturnRouteConfigurationById() {
        RouteConfiguration route = routeConfigurationService.getRouteConfigurationById("user-service");
        
        assertThat(route.id()).isEqualTo("user-service");
        assertThat(route.path()).isEqualTo("/users/**");
        assertThat(route.circuitBreakerName()).isEqualTo("user-service-cb");
    }

    @Test
    void shouldThrowExceptionWhenRouteNotFound() {
        assertThat(org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> routeConfigurationService.getRouteConfigurationById("non-existent")
        )).hasMessage("Route configuration not found: non-existent");
    }
}
