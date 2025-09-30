package com.example.gateway.infrastructure.config;

import com.example.gateway.domain.model.ServiceType;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import java.util.HashMap;
import java.util.Map;

@Component
@ConfigurationProperties(prefix = "gateway")
@Validated
public class GatewayProperties {

    @NotNull
    @Valid
    private Map<ServiceType, ServiceConfig> services = new HashMap<>();

    public Map<ServiceType, ServiceConfig> getServices() {
        return services;
    }

    public void setServices(Map<ServiceType, ServiceConfig> services) {
        this.services = services;
    }

    public ServiceConfig getServiceConfig(ServiceType serviceType) {
        return services.getOrDefault(serviceType, new ServiceConfig(serviceType.defaultUrl()));
    }

    public record ServiceConfig(
        @NotBlank String url
    ) {
        public ServiceConfig {
            if (url == null || url.isBlank()) {
                throw new IllegalArgumentException("URL cannot be null or blank");
            }
        }
    }
}
