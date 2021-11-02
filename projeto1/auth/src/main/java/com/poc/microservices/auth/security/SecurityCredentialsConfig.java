package com.poc.microservices.auth.security;

import com.poc.microservices.auth.security.filter.EnsureAuthenticatedFilter;
import com.poc.microservices.auth.security.user.UserDetailsServiceImp;
import com.poc.microservices.security.config.SecurityTokenConfig;
import com.poc.microservices.security.converter.TokenCreator;
import com.poc.microservices.security.filter.JWTTokenAuthorizationFilter;
import com.poc.microservices.security.token.TokenConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityCredentialsConfig extends SecurityTokenConfig {

    @Autowired
    private TokenCreator tokenCreator;

    @Autowired
    private UserDetailsServiceImp service;

    @Autowired
    private TokenConverter tokenConverter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .addFilter(new EnsureAuthenticatedFilter())
                .addFilterAfter(new JWTTokenAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

        super.configure(http);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(service).passwordEncoder(passwordEncoder());
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
