package com.airport.api.gateway.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

@Component
public class JwtAuthorizationGatewayFilterFactory 
    extends AbstractGatewayFilterFactory<JwtAuthorizationGatewayFilterFactory.Config> {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtAuthorizationGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            try {
                ServerHttpRequest request = exchange.getRequest();
                String method = request.getMethod().name();
                String path = request.getPath().value();
                
                System.out.println("DEBUG - JWT Filter: Processing " + method + " request to " + path);

                // Check if JWT is required for this request
                if (!requiresJwtAuthorization(method, path, config)) {
                    System.out.println("DEBUG - JWT Filter: Allowing " + method + " request without JWT check for path: " + path);
                    return chain.filter(exchange);
                }

                System.out.println("DEBUG - JWT Filter: Checking JWT for " + method + " request to " + path);

                // Extract JWT token from Authorization header
                String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                    System.out.println("DEBUG - JWT Filter: No Authorization header found");
                    return unauthorized(exchange, "Missing or invalid Authorization header");
                }

                String token = authHeader.substring(7); // Remove "Bearer " prefix
                System.out.println("DEBUG - JWT Filter: Token extracted, length: " + token.length());

                // Decode and validate JWT token
                boolean hasRole = hasRealmAdminRole(token);
                System.out.println("DEBUG - JWT Filter: Has realm-admin role: " + hasRole);
                
                if (!hasRole) {
                    return forbidden(exchange, "Insufficient permissions. realm-admin role required for " + method + " operations");
                }

                System.out.println("DEBUG - JWT Filter: Authorization successful, proceeding with request");
                // If authorized, continue with the request
                return chain.filter(exchange);

            } catch (Exception e) {
                System.err.println("JWT Filter Error: " + e.getMessage());
                e.printStackTrace();
                return unauthorized(exchange, "JWT Filter error: " + e.getMessage());
            }
        };
    }

    private boolean requiresJwtAuthorization(String method, String path, Config config) {
        // Always require JWT for POST and PUT requests
        if ("POST".equals(method) || "PUT".equals(method)) {
            return true;
        }
        
        // For GET requests, check if the path matches protected services
        if ("GET".equals(method)) {
            List<String> protectedServices = config.getProtectedServicesForGet();
            
            // Check if the path contains any of the protected service names
            for (String service : protectedServices) {
                if (path.toLowerCase().contains(service.toLowerCase())) {
                    System.out.println("DEBUG - JWT Filter: GET request to protected service: " + service);
                    return true;
                }
            }
        }
        
        return false;
    }

    private boolean hasRealmAdminRole(String token) throws Exception {
        // Split JWT token into header, payload, signature
        String[] chunks = token.split("\\.");
        if (chunks.length != 3) {
            throw new IllegalArgumentException("Invalid JWT token format");
        }

        // Decode payload (second part of JWT)
        String payload = chunks[1];
        byte[] decodedBytes = Base64.getUrlDecoder().decode(payload);
        String decodedPayload = new String(decodedBytes, StandardCharsets.UTF_8);

        // Parse JSON payload
        JsonNode jsonNode = objectMapper.readTree(decodedPayload);

        // Navigate to resource_access.realm-management.roles
        JsonNode resourceAccess = jsonNode.get("resource_access");
        if (resourceAccess == null) {
            return false;
        }

        JsonNode realmManagement = resourceAccess.get("realm-management");
        if (realmManagement == null) {
            return false;
        }

        JsonNode roles = realmManagement.get("roles");
        if (roles == null || !roles.isArray()) {
            return false;
        }

        // Check if "realm-admin" role exists (note the hyphen, not underscore)
        for (JsonNode role : roles) {
            if ("realm-admin".equals(role.asText())) {
                return true;
            }
        }

        return false;
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        return sendErrorResponse(exchange, HttpStatus.UNAUTHORIZED, message);
    }

    private Mono<Void> forbidden(ServerWebExchange exchange, String message) {
        return sendErrorResponse(exchange, HttpStatus.FORBIDDEN, message);
    }

    private Mono<Void> sendErrorResponse(ServerWebExchange exchange, HttpStatus status, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        String errorJson = String.format(
            "{\"error\": \"%s\", \"message\": \"%s\", \"timestamp\": \"%s\"}",
            status.getReasonPhrase(),
            message,
            java.time.Instant.now().toString()
        );

        DataBuffer buffer = response.bufferFactory().wrap(errorJson.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    public static class Config {
        // Configuration properties can be added here if needed
        private boolean enabled = true;
        private List<String> protectedServicesForGet = List.of("pilot", "checkin", "security");

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public List<String> getProtectedServicesForGet() {
            return protectedServicesForGet;
        }

        public void setProtectedServicesForGet(List<String> protectedServicesForGet) {
            this.protectedServicesForGet = protectedServicesForGet;
        }
    }
}