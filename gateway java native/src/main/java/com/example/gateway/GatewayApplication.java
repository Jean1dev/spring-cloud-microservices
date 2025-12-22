package com.example.gateway;

import com.example.gateway.apis.OrderApiConfig;
import com.example.gateway.apis.ProductApiConfig;
import com.example.gateway.apis.UserApiConfig;
import com.example.gateway.filters.LoggingGatewayFilterFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@SpringBootApplication
@RestController
public class GatewayApplication {

	private final UserApiConfig userApiConfig;
	private final ProductApiConfig productApiConfig;
	private final OrderApiConfig orderApiConfig;
	private final LoggingGatewayFilterFactory loggingFilterFactory;

	public GatewayApplication(UserApiConfig userApiConfig, 
	                        ProductApiConfig productApiConfig, 
	                        OrderApiConfig orderApiConfig,
	                        LoggingGatewayFilterFactory loggingFilterFactory) {
		this.userApiConfig = userApiConfig;
		this.productApiConfig = productApiConfig;
		this.orderApiConfig = orderApiConfig;
		this.loggingFilterFactory = loggingFilterFactory;
	}

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}

	@Bean
	public RouteLocator routes(RouteLocatorBuilder builder) {
		return builder.routes()
			.route("user-service", userApiConfig.buildDirectRoute(loggingFilterFactory))
			.route("product-service", productApiConfig.buildDirectRoute(loggingFilterFactory))
			.route("order-service", orderApiConfig.buildDirectRoute(loggingFilterFactory))
			.route("user-service-prefix", userApiConfig.buildPrefixedRoute(loggingFilterFactory))
			.route("product-service-prefix", productApiConfig.buildPrefixedRoute(loggingFilterFactory))
			.route("order-service-prefix", orderApiConfig.buildPrefixedRoute(loggingFilterFactory))
			.build();
	}

	@RequestMapping("/fallback/user")
	public Mono<String> userFallback() {
		return Mono.just("{\"service\": \"user-service\", \"message\": \"Serviço temporariamente indisponível\", \"status\": \"fallback\"}");
	}

	@RequestMapping("/fallback/product")
	public Mono<String> productFallback() {
		return Mono.just("{\"service\": \"product-service\", \"message\": \"Serviço temporariamente indisponível\", \"status\": \"fallback\"}");
	}

	@RequestMapping("/fallback/order")
	public Mono<String> orderFallback() {
		return Mono.just("{\"service\": \"order-service\", \"message\": \"Serviço temporariamente indisponível\", \"status\": \"fallback\"}");
	}
}
