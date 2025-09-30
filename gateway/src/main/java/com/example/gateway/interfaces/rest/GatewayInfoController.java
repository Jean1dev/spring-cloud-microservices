package com.example.gateway.interfaces.rest;

import com.example.gateway.application.port.RouteConfigurationPort;
import com.example.gateway.domain.model.RouteConfiguration;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/gateway")
public class GatewayInfoController {

    private final RouteConfigurationPort routeConfigurationPort;

    public GatewayInfoController(RouteConfigurationPort routeConfigurationPort) {
        this.routeConfigurationPort = routeConfigurationPort;
    }

    @GetMapping("/routes")
    public Flux<RouteConfiguration> getAllRoutes() {
        return routeConfigurationPort.getAllRouteConfigurations();
    }

    @GetMapping("/routes/{id}")
    public Mono<ResponseEntity<RouteConfiguration>> getRouteById(@PathVariable String id) {
        try {
            RouteConfiguration route = routeConfigurationPort.getRouteConfigurationById(id);
            return Mono.just(ResponseEntity.ok(route));
        } catch (IllegalArgumentException e) {
            return Mono.just(ResponseEntity.notFound().build());
        }
    }

    @GetMapping("/health")
    public Mono<ResponseEntity<String>> health() {
        return Mono.just(ResponseEntity.ok("Gateway is healthy"));
    }
}
