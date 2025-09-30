package com.example.gateway;

import com.example.gateway.infrastructure.adapter.SpringCloudGatewayAdapter;
import com.example.gateway.infrastructure.config.CircuitBreakerProperties;
import com.example.gateway.infrastructure.config.GatewayProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableConfigurationProperties({GatewayProperties.class, CircuitBreakerProperties.class})
public class GatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}

	@Bean
	public RouteLocator routeLocator(RouteLocatorBuilder builder, SpringCloudGatewayAdapter gatewayAdapter) {
		return gatewayAdapter.createRoutes(builder);
	}
}
