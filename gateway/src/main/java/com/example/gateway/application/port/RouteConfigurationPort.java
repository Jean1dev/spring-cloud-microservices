package com.example.gateway.application.port;

import com.example.gateway.domain.model.RouteConfiguration;
import reactor.core.publisher.Flux;

public interface RouteConfigurationPort {
    Flux<RouteConfiguration> getAllRouteConfigurations();
    RouteConfiguration getRouteConfigurationById(String id);
}
