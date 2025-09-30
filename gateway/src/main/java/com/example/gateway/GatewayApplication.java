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
			.route("user-service", r -> r.path(userApiConfig.getDirectPath())
				.filters(f -> f
					.filter(loggingFilterFactory.apply(config -> config.setTargetService("user-service")))
					.circuitBreaker(config -> config
						.setName(userApiConfig.getCircuitBreakerName())
						.setFallbackUri(userApiConfig.getFallbackUri())))
				.uri(userApiConfig.getServiceUrl()))
			.route("product-service", r -> r.path(productApiConfig.getDirectPath())
				.filters(f -> f
					.filter(loggingFilterFactory.apply(config -> config.setTargetService("product-service")))
					.circuitBreaker(config -> config
						.setName(productApiConfig.getCircuitBreakerName())
						.setFallbackUri(productApiConfig.getFallbackUri())))
				.uri(productApiConfig.getServiceUrl()))
			.route("order-service", r -> r.path(orderApiConfig.getDirectPath())
				.filters(f -> f
					.filter(loggingFilterFactory.apply(config -> config.setTargetService("order-service")))
					.circuitBreaker(config -> config
						.setName(orderApiConfig.getCircuitBreakerName())
						.setFallbackUri(orderApiConfig.getFallbackUri())))
				.uri(orderApiConfig.getServiceUrl()))
			.route("user-service-prefix", r -> r.path(userApiConfig.getPrefixedPath())
				.filters(f -> f
					.filter(loggingFilterFactory.apply(config -> config.setTargetService("user-service")))
					.rewritePath(userApiConfig.getRewritePath(), userApiConfig.getRewriteReplacement())
					.circuitBreaker(config -> config
						.setName(userApiConfig.getCircuitBreakerName())
						.setFallbackUri(userApiConfig.getFallbackUri())))
				.uri(userApiConfig.getServiceUrl()))
			.route("product-service-prefix", r -> r.path(productApiConfig.getPrefixedPath())
				.filters(f -> f
					.filter(loggingFilterFactory.apply(config -> config.setTargetService("product-service")))
					.rewritePath(productApiConfig.getRewritePath(), productApiConfig.getRewriteReplacement())
					.circuitBreaker(config -> config
						.setName(productApiConfig.getCircuitBreakerName())
						.setFallbackUri(productApiConfig.getFallbackUri())))
				.uri(productApiConfig.getServiceUrl()))
			.route("order-service-prefix", r -> r.path(orderApiConfig.getPrefixedPath())
				.filters(f -> f
					.filter(loggingFilterFactory.apply(config -> config.setTargetService("order-service")))
					.rewritePath(orderApiConfig.getRewritePath(), orderApiConfig.getRewriteReplacement())
					.circuitBreaker(config -> config
						.setName(orderApiConfig.getCircuitBreakerName())
						.setFallbackUri(orderApiConfig.getFallbackUri())))
				.uri(orderApiConfig.getServiceUrl()))
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
