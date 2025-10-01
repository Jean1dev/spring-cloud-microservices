package com.example.gateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${keycloak.enabled}")
    private Boolean keycloakEnabled;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        if (!keycloakEnabled) {
            return http
                    .authorizeExchange(exchanges -> exchanges.anyExchange().permitAll())
                    .csrf(ServerHttpSecurity.CsrfSpec::disable)
                    .build();
        }

        return http
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/actuator/**").permitAll()
                        .pathMatchers("/health").permitAll()
                        .anyExchange().authenticated()
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .oauth2Login(Customizer.withDefaults())
                .oauth2ResourceServer(conf -> conf.jwt(Customizer.withDefaults()))
                .build();
    }
}
