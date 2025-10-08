package com.example.gateway.security;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

@TestConfiguration
@EnableWebFluxSecurity
@Profile("test")
public class TestSecurityConfig {

    @Bean
    @Primary
    public SecurityWebFilterChain testSecurityWebFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(exchanges -> exchanges.anyExchange().permitAll())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

    @Bean
    @Primary
    public ReactiveClientRegistrationRepository testClientRegistrationRepository() {
        return new ReactiveClientRegistrationRepository() {
            @Override
            public Mono<org.springframework.security.oauth2.client.registration.ClientRegistration> findByRegistrationId(String registrationId) {
                return Mono.empty();
            }
        };
    }

    @Bean
    @Primary
    public ServerOAuth2AuthorizedClientRepository testAuthorizedClientRepository() {
        return new ServerOAuth2AuthorizedClientRepository() {
            @Override
            public <T extends org.springframework.security.oauth2.client.OAuth2AuthorizedClient> Mono<T> loadAuthorizedClient(String clientRegistrationId, org.springframework.security.core.Authentication principal, org.springframework.web.server.ServerWebExchange exchange) {
                return Mono.empty();
            }

            @Override
            public Mono<Void> saveAuthorizedClient(org.springframework.security.oauth2.client.OAuth2AuthorizedClient authorizedClient, org.springframework.security.core.Authentication principal, org.springframework.web.server.ServerWebExchange exchange) {
                return Mono.empty();
            }

            @Override
            public Mono<Void> removeAuthorizedClient(String clientRegistrationId, org.springframework.security.core.Authentication principal, org.springframework.web.server.ServerWebExchange exchange) {
                return Mono.empty();
            }
        };
    }

    @Bean
    @Primary
    public ReactiveJwtDecoder testJwtDecoder() {
        return token -> Mono.empty();
    }
}
