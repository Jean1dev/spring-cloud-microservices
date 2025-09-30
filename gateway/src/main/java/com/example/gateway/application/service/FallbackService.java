package com.example.gateway.application.service;

import com.example.gateway.application.port.FallbackServicePort;
import com.example.gateway.domain.model.FallbackResponse;
import com.example.gateway.domain.model.ServiceType;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class FallbackService implements FallbackServicePort {

    @Override
    public Mono<FallbackResponse> getFallbackResponse(ServiceType serviceType) {
        return Mono.just(FallbackResponse.serviceUnavailable(serviceType.getName()));
    }
}
