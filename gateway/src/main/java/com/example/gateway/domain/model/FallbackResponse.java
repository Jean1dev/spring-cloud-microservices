package com.example.gateway.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

public record FallbackResponse(
    @JsonProperty("service") String service,
    @JsonProperty("message") String message,
    @JsonProperty("status") String status
) {
    
    public FallbackResponse {
        Objects.requireNonNull(service, "Service cannot be null");
        Objects.requireNonNull(message, "Message cannot be null");
        Objects.requireNonNull(status, "Status cannot be null");
    }

    public static FallbackResponse serviceUnavailable(String serviceName) {
        return new FallbackResponse(
            serviceName,
            "Serviço temporariamente indisponível",
            "fallback"
        );
    }
}
