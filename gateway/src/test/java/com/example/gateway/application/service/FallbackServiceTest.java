package com.example.gateway.application.service;

import com.example.gateway.domain.model.ServiceType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

class FallbackServiceTest {

    private FallbackService fallbackService;

    @BeforeEach
    void setUp() {
        fallbackService = new FallbackService();
    }

    @Test
    void shouldReturnFallbackResponseForUserService() {
        StepVerifier.create(fallbackService.getFallbackResponse(ServiceType.USER_SERVICE))
                .assertNext(response -> {
                    assertThat(response.service()).isEqualTo("user-service");
                    assertThat(response.message()).isEqualTo("Serviço temporariamente indisponível");
                    assertThat(response.status()).isEqualTo("fallback");
                })
                .verifyComplete();
    }

    @Test
    void shouldReturnFallbackResponseForProductService() {
        StepVerifier.create(fallbackService.getFallbackResponse(ServiceType.PRODUCT_SERVICE))
                .assertNext(response -> {
                    assertThat(response.service()).isEqualTo("product-service");
                    assertThat(response.message()).isEqualTo("Serviço temporariamente indisponível");
                    assertThat(response.status()).isEqualTo("fallback");
                })
                .verifyComplete();
    }

    @Test
    void shouldReturnFallbackResponseForOrderService() {
        StepVerifier.create(fallbackService.getFallbackResponse(ServiceType.ORDER_SERVICE))
                .assertNext(response -> {
                    assertThat(response.service()).isEqualTo("order-service");
                    assertThat(response.message()).isEqualTo("Serviço temporariamente indisponível");
                    assertThat(response.status()).isEqualTo("fallback");
                })
                .verifyComplete();
    }
}
