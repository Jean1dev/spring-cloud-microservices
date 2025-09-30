package com.example.gateway.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ServiceTypeTest {

    @Test
    void shouldReturnCorrectServiceTypeFromName() {
        assertThat(ServiceType.fromName("user-service")).isEqualTo(ServiceType.USER_SERVICE);
        assertThat(ServiceType.fromName("product-service")).isEqualTo(ServiceType.PRODUCT_SERVICE);
        assertThat(ServiceType.fromName("order-service")).isEqualTo(ServiceType.ORDER_SERVICE);
    }

    @Test
    void shouldThrowExceptionForUnknownServiceType() {
        assertThatThrownBy(() -> ServiceType.fromName("unknown-service"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unknown service type: unknown-service");
    }

    @Test
    void shouldReturnCorrectDefaultUrls() {
        assertThat(ServiceType.USER_SERVICE.defaultUrl()).isEqualTo("http://localhost:8080");
        assertThat(ServiceType.PRODUCT_SERVICE.defaultUrl()).isEqualTo("http://localhost:8081");
        assertThat(ServiceType.ORDER_SERVICE.defaultUrl()).isEqualTo("http://localhost:8082");
    }

    @Test
    void shouldReturnCorrectNames() {
        assertThat(ServiceType.USER_SERVICE.name()).isEqualTo("user-service");
        assertThat(ServiceType.PRODUCT_SERVICE.name()).isEqualTo("product-service");
        assertThat(ServiceType.ORDER_SERVICE.name()).isEqualTo("order-service");
    }

    @Test
    void shouldReturnCorrectFallbackPaths() {
        assertThat(ServiceType.USER_SERVICE.getFallbackPath()).isEqualTo("/fallback/user");
        assertThat(ServiceType.PRODUCT_SERVICE.getFallbackPath()).isEqualTo("/fallback/product");
        assertThat(ServiceType.ORDER_SERVICE.getFallbackPath()).isEqualTo("/fallback/order");
    }

    @Test
    void shouldReturnCorrectCircuitBreakerNames() {
        assertThat(ServiceType.USER_SERVICE.getCircuitBreakerName()).isEqualTo("user-service-cb");
        assertThat(ServiceType.PRODUCT_SERVICE.getCircuitBreakerName()).isEqualTo("product-service-cb");
        assertThat(ServiceType.ORDER_SERVICE.getCircuitBreakerName()).isEqualTo("order-service-cb");
    }

    @Test
    void shouldReturnCorrectDirectPaths() {
        assertThat(ServiceType.USER_SERVICE.getDirectPath()).isEqualTo("/users/**");
        assertThat(ServiceType.PRODUCT_SERVICE.getDirectPath()).isEqualTo("/products/**");
        assertThat(ServiceType.ORDER_SERVICE.getDirectPath()).isEqualTo("/orders/**");
    }

    @Test
    void shouldReturnCorrectPrefixedPaths() {
        assertThat(ServiceType.USER_SERVICE.getPrefixedPath()).isEqualTo("/user-service/**");
        assertThat(ServiceType.PRODUCT_SERVICE.getPrefixedPath()).isEqualTo("/product-service/**");
        assertThat(ServiceType.ORDER_SERVICE.getPrefixedPath()).isEqualTo("/order-service/**");
    }
}
