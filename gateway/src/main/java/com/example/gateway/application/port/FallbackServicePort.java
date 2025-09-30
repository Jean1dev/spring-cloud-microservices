package com.example.gateway.application.port;

import com.example.gateway.domain.model.FallbackResponse;
import com.example.gateway.domain.model.ServiceType;
import reactor.core.publisher.Mono;

public interface FallbackServicePort {
    Mono<FallbackResponse> getFallbackResponse(ServiceType serviceType);
}
