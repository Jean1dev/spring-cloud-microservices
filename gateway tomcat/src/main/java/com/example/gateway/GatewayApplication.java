package com.example.gateway;

import com.example.gateway.apis.OrderApiConfig;
import com.example.gateway.apis.ProductApiConfig;
import com.example.gateway.apis.UserApiConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

@SpringBootApplication
@RestController
public class GatewayApplication {

	private final UserApiConfig userApiConfig;
	private final ProductApiConfig productApiConfig;
	private final OrderApiConfig orderApiConfig;

	public GatewayApplication(UserApiConfig userApiConfig, 
	                        ProductApiConfig productApiConfig, 
	                        OrderApiConfig orderApiConfig) {
		this.userApiConfig = userApiConfig;
		this.productApiConfig = productApiConfig;
		this.orderApiConfig = orderApiConfig;
	}

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}

	@Bean
	public RouterFunction<ServerResponse> routes() {
		return RouterFunctions.route()
			.add(userApiConfig.buildDirectRoute())
			.add(productApiConfig.buildDirectRoute())
			.add(orderApiConfig.buildDirectRoute())
			.add(userApiConfig.buildPrefixedRoute())
			.add(productApiConfig.buildPrefixedRoute())
			.add(orderApiConfig.buildPrefixedRoute())
			.build();
	}

	@RequestMapping("/fallback/user")
	public String userFallback() {
		return "{\"service\": \"user-service\", \"message\": \"Serviço temporariamente indisponível\", \"status\": \"fallback\"}";
	}

	@RequestMapping("/fallback/product")
	public String productFallback() {
		return "{\"service\": \"product-service\", \"message\": \"Serviço temporariamente indisponível\", \"status\": \"fallback\"}";
	}

	@RequestMapping("/fallback/order")
	public String orderFallback() {
		return "{\"service\": \"order-service\", \"message\": \"Serviço temporariamente indisponível\", \"status\": \"fallback\"}";
	}
}
