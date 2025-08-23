package com.airport.api.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.issuer}")
    private String jwtIssuer;

    public JwtAuthFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String path = exchange.getRequest().getPath().toString();
            String method = exchange.getRequest().getMethod().toString();
            
            logger.info("JWT Filter - Processing request: {} {}", method, path);
            
            // Skip JWT validation for auth endpoints
            if (isAuthPath(path)) {
                logger.info("JWT Filter - Skipping auth validation for path: {}", path);
                return chain.filter(exchange);
            }

            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            logger.info("JWT Filter - Authorization header: {}", authHeader != null ? "Present" : "Missing");

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                logger.warn("JWT Filter - Missing or invalid Authorization header for path: {}", path);
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Missing or invalid Authorization header");
            }

            try {
                String token = authHeader.substring(7);
                logger.info("JWT Filter - Validating token for path: {}", path);
                
                // Create secret key from the secret string
                SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
                
                // Parse and validate the JWT token
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(key)
                        .requireIssuer(jwtIssuer)  // Validate issuer
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                logger.info("JWT Filter - Token validated successfully. Subject: {}", claims.getSubject());

                // Add user information to request headers for downstream services
                exchange = exchange.mutate().request(r -> r.headers(h -> {
                    h.add("X-User-Id", claims.getSubject());
                    if (claims.get("username") != null) {
                        h.add("X-Username", claims.get("username").toString());
                    }
                    if (claims.get("authorities") != null) {
                        h.add("X-User-Authorities", claims.get("authorities").toString());
                    }
                    logger.debug("Added user headers: X-User-Id={}", claims.getSubject());
                })).build();

                return chain.filter(exchange);

            } catch (Exception e) {
                logger.error("JWT Filter - Token validation failed for path: {}, Error: {}", path, e.getMessage());
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Invalid JWT token: " + e.getMessage());
            }
        };
    }

    private boolean isAuthPath(String path) {
        return path.startsWith("/auth/") || 
               path.startsWith("/airport-auth-service/") ||
               path.equals("/auth") ||
               path.equals("/airport-auth-service");
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status, String message) {
        logger.error("JWT Filter - Returning error: {} - {}", status, message);
        
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        
        String errorBody = String.format("{\"error\": \"%s\", \"message\": \"%s\", \"timestamp\": \"%s\"}", 
                                        status.getReasonPhrase(), 
                                        message,
                                        java.time.Instant.now());
        
        DataBuffer dataBuffer = exchange.getResponse().bufferFactory().wrap(errorBody.getBytes(StandardCharsets.UTF_8));
        return exchange.getResponse().writeWith(Mono.just(dataBuffer));
    }

    public static class Config {
        // Configuration properties can be added here if needed
    }
}