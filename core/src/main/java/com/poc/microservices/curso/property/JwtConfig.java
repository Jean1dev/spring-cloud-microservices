package com.poc.microservices.curso.property;

import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt.config")
@Getter
public class JwtConfig {

    private final String loginUrl = "/login/**";

    @NestedConfigurationProperty
    private final Header header = new Header();

    private final int expiration = 3600;

    private final String privateKey = "auhsuahsouahosuaho";

    private final String type = "encrypted";

    @Getter
    public static class Header {
        private final String name = "Authorization";
        private final String prefix = "Bearer ";
    }
}
