package com.example.gateway.apis;

import com.example.gateway.ApplicationTestsNoAuth;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

class UserApiConfigTest extends ApplicationTestsNoAuth {

    @Autowired
    private UserApiConfig userApiConfig;

    @Test
    void shouldReturnCorrectServiceUrl() {
        assertThat(userApiConfig.getServiceUrl()).isEqualTo("http://localhost:8080");
    }

    @Test
    void shouldReturnCorrectCircuitBreakerName() {
        assertThat(userApiConfig.getCircuitBreakerName()).isEqualTo("user-cb");
    }

    @Test
    void shouldReturnCorrectFallbackUri() {
        assertThat(userApiConfig.getFallbackUri()).isEqualTo("forward:/fallback/user");
    }

    @Test
    void shouldReturnCorrectDirectPath() {
        assertThat(userApiConfig.getDirectPath()).isEqualTo("/users/**");
    }

    @Test
    void shouldReturnCorrectPrefixedPath() {
        assertThat(userApiConfig.getPrefixedPath()).isEqualTo("/user-service/**");
    }
}
