package com.example.gateway.filters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class LoggingGatewayFilterFactory extends AbstractGatewayFilterFactory<LoggingGatewayFilterFactory.Config> {

    private static final Logger logger = LoggerFactory.getLogger(LoggingGatewayFilterFactory.class);
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    public LoggingGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String timestamp = LocalDateTime.now().format(formatter);

            logger.info("🚀 [{}] INCOMING REQUEST: {} {} -> Target: {}",
                timestamp,
                request.getMethod(),
                request.getURI(),
                config.getTargetService()
            );

            logger.info("📋 [{}] Headers - Host: {}, User-Agent: {}, X-Forwarded-For: {}",
                timestamp,
                request.getHeaders().getFirst("Host"),
                request.getHeaders().getFirst("User-Agent"),
                request.getHeaders().getFirst("X-Forwarded-For")
            );

            if (!request.getQueryParams().isEmpty()) {
                logger.info("🔍 [{}] Query Params: {}", timestamp, request.getQueryParams());
            }
            
            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                String responseTimestamp = LocalDateTime.now().format(formatter);
                logger.info("✅ [{}] RESPONSE SENT: {} {} -> Status: {}",
                    responseTimestamp,
                    request.getMethod(),
                    request.getURI(),
                    exchange.getResponse().getStatusCode()
                );
            }));
        };
    }

    public static class Config {
        private String targetService;

        public String getTargetService() {
            return targetService;
        }

        public void setTargetService(String targetService) {
            this.targetService = targetService;
        }
    }
}
