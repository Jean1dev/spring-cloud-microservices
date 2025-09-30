package com.example.gateway.apis;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class UserApiConfigTest {

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
