package com.example.gateway.application.service;

import com.example.gateway.application.port.RouteConfigurationPort;
import com.example.gateway.domain.model.RouteConfiguration;
import com.example.gateway.domain.model.ServiceType;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

import java.util.Arrays;
import java.util.List;

@Service
public class RouteConfigurationService implements RouteConfigurationPort {
    
    private final List<RouteConfiguration> routeConfigurations;

    public RouteConfigurationService() {
        this.routeConfigurations = initializeRouteConfigurations();
    }

    @Override
    public Flux<RouteConfiguration> getAllRouteConfigurations() {
        return Flux.fromIterable(routeConfigurations);
    }

    @Override
    public RouteConfiguration getRouteConfigurationById(String id) {
        return routeConfigurations.stream()
                .filter(route -> route.getId().equals(id))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Route configuration not found: " + id));
    }

    private List<RouteConfiguration> initializeRouteConfigurations() {
        return Arrays.asList(
            createDirectRoute(ServiceType.USER_SERVICE),
            createDirectRoute(ServiceType.PRODUCT_SERVICE),
            createDirectRoute(ServiceType.ORDER_SERVICE),
            createPrefixedRoute(ServiceType.USER_SERVICE),
            createPrefixedRoute(ServiceType.PRODUCT_SERVICE),
            createPrefixedRoute(ServiceType.ORDER_SERVICE)
        );
    }

    private RouteConfiguration createDirectRoute(ServiceType serviceType) {
        return RouteConfiguration.builder()
                .id(serviceType.name())
                .path(serviceType.getDirectPath())
                .uri(serviceType.defaultUrl())
                .circuitBreakerName(serviceType.getCircuitBreakerName())
                .fallbackUri("forward:" + serviceType.getFallbackPath())
                .build();
    }

    private RouteConfiguration createPrefixedRoute(ServiceType serviceType) {
        return RouteConfiguration.builder()
                .id(serviceType.name() + "-prefix")
                .path(serviceType.getPrefixedPath())
                .uri(serviceType.defaultUrl())
                .circuitBreakerName(serviceType.getCircuitBreakerName())
                .fallbackUri("forward:" + serviceType.getFallbackPath())
                .build();
    }
}
