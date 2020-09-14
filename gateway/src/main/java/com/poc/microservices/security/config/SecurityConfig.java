package com.poc.microservices.security.config;

import com.poc.microservices.curso.property.JwtConfig;
import com.poc.microservices.security.filter.GatewayAuthorizationFilter;
import com.poc.microservices.security.token.TokenConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig extends SecurityTokenConfig {

    private final JwtConfig jwtConfig = new JwtConfig();

    @Autowired
    private TokenConverter tokenConverter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterAfter(new GatewayAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
        super.configure(http);
    }
}
