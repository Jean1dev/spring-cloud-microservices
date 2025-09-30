package com.example.gateway.interfaces.rest;

import com.example.gateway.application.port.FallbackServicePort;
import com.example.gateway.domain.model.FallbackResponse;
import com.example.gateway.domain.model.ServiceType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/fallback")
public class FallbackController {

    private final FallbackServicePort fallbackService;

    public FallbackController(FallbackServicePort fallbackService) {
        this.fallbackService = fallbackService;
    }

    @GetMapping("/user")
    public Mono<ResponseEntity<FallbackResponse>> userFallback() {
        return fallbackService.getFallbackResponse(ServiceType.USER_SERVICE)
                .map(ResponseEntity::ok);
    }

    @GetMapping("/product")
    public Mono<ResponseEntity<FallbackResponse>> productFallback() {
        return fallbackService.getFallbackResponse(ServiceType.PRODUCT_SERVICE)
                .map(ResponseEntity::ok);
    }

    @GetMapping("/order")
    public Mono<ResponseEntity<FallbackResponse>> orderFallback() {
        return fallbackService.getFallbackResponse(ServiceType.ORDER_SERVICE)
                .map(ResponseEntity::ok);
    }

    @GetMapping("/{serviceType}")
    public Mono<ResponseEntity<FallbackResponse>> genericFallback(@PathVariable String serviceType) {
        try {
            ServiceType type = ServiceType.fromName(serviceType);
            return fallbackService.getFallbackResponse(type)
                    .map(ResponseEntity::ok);
        } catch (IllegalArgumentException e) {
            return Mono.just(ResponseEntity.badRequest().build());
        }
    }
}
