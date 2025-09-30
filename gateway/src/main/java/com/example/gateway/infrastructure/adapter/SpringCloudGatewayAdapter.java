package com.example.gateway.infrastructure.adapter;

import com.example.gateway.application.port.RouteConfigurationPort;
import com.example.gateway.domain.model.ServiceType;
import com.example.gateway.infrastructure.config.GatewayProperties;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.stereotype.Component;

@Component
public class SpringCloudGatewayAdapter {

    private final RouteConfigurationPort routeConfigurationPort;
    private final GatewayProperties gatewayProperties;

    public SpringCloudGatewayAdapter(RouteConfigurationPort routeConfigurationPort, 
                                   GatewayProperties gatewayProperties) {
        this.routeConfigurationPort = routeConfigurationPort;
        this.gatewayProperties = gatewayProperties;
    }

    public RouteLocator createRoutes(RouteLocatorBuilder builder) {
        return builder.routes()
                .route(createUserServiceRoute())
                .route(createProductServiceRoute())
                .route(createOrderServiceRoute())
                .route(createUserServicePrefixedRoute())
                .route(createProductServicePrefixedRoute())
                .route(createOrderServicePrefixedRoute())
                .build();
    }

    private RouteLocatorBuilder.Builder createUserServiceRoute() {
        return createRouteBuilder(ServiceType.USER_SERVICE, "/users/**", false);
    }

    private RouteLocatorBuilder.Builder createProductServiceRoute() {
        return createRouteBuilder(ServiceType.PRODUCT_SERVICE, "/products/**", false);
    }

    private RouteLocatorBuilder.Builder createOrderServiceRoute() {
        return createRouteBuilder(ServiceType.ORDER_SERVICE, "/orders/**", false);
    }

    private RouteLocatorBuilder.Builder createUserServicePrefixedRoute() {
        return createRouteBuilder(ServiceType.USER_SERVICE, "/user-service/**", true);
    }

    private RouteLocatorBuilder.Builder createProductServicePrefixedRoute() {
        return createRouteBuilder(ServiceType.PRODUCT_SERVICE, "/product-service/**", true);
    }

    private RouteLocatorBuilder.Builder createOrderServicePrefixedRoute() {
        return createRouteBuilder(ServiceType.ORDER_SERVICE, "/order-service/**", true);
    }

    private RouteLocatorBuilder.Builder createRouteBuilder(ServiceType serviceType, String path, boolean isPrefixed) {
        String serviceUrl = gatewayProperties.getServiceConfig(serviceType).url();
        String circuitBreakerName = serviceType.getCircuitBreakerName();
        String fallbackUri = "forward:" + serviceType.getFallbackPath();

        RouteLocatorBuilder.Builder routeBuilder = RouteLocatorBuilder.Builder()
                .path(path)
                .filters(f -> {
                    if (isPrefixed) {
                        String rewritePath = "/" + serviceType.name() + "/(?<segment>.*)";
                        f.rewritePath(rewritePath, "/${segment}");
                    }
                    return f.circuitBreaker(config -> config
                            .setName(circuitBreakerName)
                            .setFallbackUri(fallbackUri));
                })
                .uri(serviceUrl);

        return routeBuilder;
    }
}
