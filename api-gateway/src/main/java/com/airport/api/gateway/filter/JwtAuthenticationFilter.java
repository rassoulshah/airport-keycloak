package com.airport.api.gateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    @Value("${keycloak.auth-server-url}")
    private String keycloakServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    private final WebClient webClient;
    private String userInfoEndpoint;

    public JwtAuthenticationFilter() {
        super(Config.class);
        this.webClient = WebClient.builder().build();
    }

    @PostConstruct
    public void init() {
        this.userInfoEndpoint = String.format("%s/realms/%s/protocol/openid-connect/userinfo", 
                keycloakServerUrl, realm);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // Check if Authorization header is present
            if (!isAuthPresent(request)) {
                return onError(exchange, "Authorization header is missing", HttpStatus.UNAUTHORIZED);
            }

            String token = getAuthHeader(request);
            
            // Validate token with Keycloak
            return validateTokenWithKeycloak(token)
                    .flatMap(isValid -> {
                        if (isValid) {
                            // Add user info to request headers if needed
                            ServerHttpRequest modifiedRequest = request.mutate()
                                    .header("X-User-Token", token)
                                    .build();
                            
                            return chain.filter(exchange.mutate().request(modifiedRequest).build());
                        } else {
                            return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
                        }
                    })
                    .onErrorResume(throwable -> {
                        System.err.println("Token validation error: " + throwable.getMessage());
                        return onError(exchange, "Token validation failed", HttpStatus.UNAUTHORIZED);
                    });
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().add("Content-Type", "application/json");
        
        String errorBody = String.format("{\"error\": \"%s\", \"status\": %d}", err, httpStatus.value());
        
        return response.writeWith(Mono.just(response.bufferFactory().wrap(errorBody.getBytes())));
    }

    private String getAuthHeader(ServerHttpRequest request) {
        String authHeader = request.getHeaders().getOrEmpty("Authorization").get(0);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return authHeader;
    }

    private boolean isAuthPresent(ServerHttpRequest request) {
        return request.getHeaders().containsKey("Authorization");
    }

    private Mono<Boolean> validateTokenWithKeycloak(String token) {
        return webClient.get()
                .uri(userInfoEndpoint)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .toEntity(String.class)
                .map(response -> response.getStatusCode().is2xxSuccessful())
                .onErrorReturn(false);
    }

    public static class Config {
        // Configuration properties if needed
        private String name;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }
    }
}