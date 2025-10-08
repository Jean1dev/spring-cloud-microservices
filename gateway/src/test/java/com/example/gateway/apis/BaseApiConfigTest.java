package com.example.gateway.apis;

import com.example.gateway.ApplicationTestsNoAuth;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

class BaseApiConfigTest extends ApplicationTestsNoAuth {

    @Autowired
    private UserApiConfig userApiConfig;

    @Autowired
    private ProductApiConfig productApiConfig;

    @Autowired
    private OrderApiConfig orderApiConfig;

    @Test
    void shouldHaveCorrectCircuitBreakerNames() {
        assertThat(userApiConfig.getCircuitBreakerName()).isEqualTo("user-cb");
        assertThat(productApiConfig.getCircuitBreakerName()).isEqualTo("product-cb");
        assertThat(orderApiConfig.getCircuitBreakerName()).isEqualTo("order-cb");
    }

    @Test
    void shouldHaveCorrectFallbackUris() {
        assertThat(userApiConfig.getFallbackUri()).isEqualTo("forward:/fallback/user");
        assertThat(productApiConfig.getFallbackUri()).isEqualTo("forward:/fallback/product");
        assertThat(orderApiConfig.getFallbackUri()).isEqualTo("forward:/fallback/order");
    }

    @Test
    void shouldHaveCorrectDirectPaths() {
        assertThat(userApiConfig.getDirectPath()).isEqualTo("/users/**");
        assertThat(productApiConfig.getDirectPath()).isEqualTo("/products/**");
        assertThat(orderApiConfig.getDirectPath()).isEqualTo("/orders/**");
    }

    @Test
    void shouldHaveCorrectPrefixedPaths() {
        assertThat(userApiConfig.getPrefixedPath()).isEqualTo("/user-service/**");
        assertThat(productApiConfig.getPrefixedPath()).isEqualTo("/product-service/**");
        assertThat(orderApiConfig.getPrefixedPath()).isEqualTo("/order-service/**");
    }
}
