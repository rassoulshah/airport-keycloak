package com.airport.bookings.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Component
public class JwtUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Extracts JWT token from Authorization header
     * @param request HTTP request containing Authorization header
     * @return JWT token string without "Bearer " prefix, or null if not found
     */
    public String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Remove "Bearer " prefix
        }
        return null;
    }

    /**
     * Decodes JWT token payload without verification
     * WARNING: This method does not verify the token signature.
     * In production, you should verify the JWT signature using Keycloak's public key.
     * @param token JWT token string
     * @return Map containing decoded token payload
     * @throws RuntimeException if token cannot be decoded
     */
    public Map<String, Object> decodeJwtToken(String token) {
        try {
            // Decode JWT token (without verification for now - you should verify in production)
            String[] chunks = token.split("\\.");
            if (chunks.length != 3) {
                throw new IllegalArgumentException("Invalid JWT token format");
            }
            
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String payload = new String(decoder.decode(chunks[1]));
            
            // Parse JSON payload
            return objectMapper.readValue(payload, Map.class);
            
        } catch (Exception e) {
            log.error("Failed to decode JWT token: {}", e.getMessage());
            throw new RuntimeException("Failed to decode JWT token", e);
        }
    }

    /**
     * Checks if user has realm-admin role based on JWT token payload
     * @param decodedToken Map containing decoded JWT token payload
     * @return true if user has realm-admin role, false otherwise
     */
    public boolean isUserAdmin(Map<String, Object> decodedToken) {
        try {
            // Navigate to resource_access['realm-management']?.roles
            Map<String, Object> resourceAccess = (Map<String, Object>) decodedToken.get("resource_access");
            
            if (resourceAccess == null) {
                log.debug("No resource_access found in token");
                return false;
            }
            
            Map<String, Object> realmManagement = (Map<String, Object>) resourceAccess.get("realm-management");
            
            if (realmManagement == null) {
                log.debug("No realm-management found in resource_access");
                return false;
            }
            
            List<String> roles = (List<String>) realmManagement.get("roles");
            
            if (roles == null) {
                log.debug("No roles found in realm-management");
                return false;
            }
            
            boolean isAdmin = roles.contains("realm-admin");
            log.debug("User admin status: {}, roles: {}", isAdmin, roles);
            return isAdmin;
            
        } catch (Exception e) {
            log.error("Error checking admin role: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Extracts user ID from JWT token payload
     * @param decodedToken Map containing decoded JWT token payload
     * @return User ID string, or null if not found
     */
    public String getUserIdFromToken(Map<String, Object> decodedToken) {
        // Extract user ID from token (adjust field name as needed)
        // Common fields: "sub", "user_id", "preferred_username", "email"
        String userId = (String) decodedToken.get("email"); // Use email as primary identifier
        
        if (userId == null) {
            // Fallback to other common fields
            userId = (String) decodedToken.get("sub");
        }
        
        if (userId == null) {
            userId = (String) decodedToken.get("preferred_username");
        }
        
        log.debug("Extracted user ID: {}", userId);
        return userId;
    }

    /**
     * Extracts user email from JWT token payload
     * @param decodedToken Map containing decoded JWT token payload
     * @return User email string, or null if not found
     */
    public String getUserEmailFromToken(Map<String, Object> decodedToken) {
        return (String) decodedToken.get("email");
    }

    /**
     * Extracts username from JWT token payload
     * @param decodedToken Map containing decoded JWT token payload
     * @return Username string, or null if not found
     */
    public String getUsernameFromToken(Map<String, Object> decodedToken) {
        return (String) decodedToken.get("preferred_username");
    }

    /**
     * Gets all roles from JWT token
     * @param decodedToken Map containing decoded JWT token payload
     * @return List of realm roles, or empty list if none found
     */
    @SuppressWarnings("unchecked")
    public List<String> getRealmRoles(Map<String, Object> decodedToken) {
        try {
            Map<String, Object> realmAccess = (Map<String, Object>) decodedToken.get("realm_access");
            if (realmAccess != null) {
                List<String> roles = (List<String>) realmAccess.get("roles");
                return roles != null ? roles : List.of();
            }
            return List.of();
        } catch (Exception e) {
            log.error("Error extracting realm roles: {}", e.getMessage());
            return List.of();
        }
    }

    /**
     * Checks if token is expired
     * @param decodedToken Map containing decoded JWT token payload
     * @return true if token is expired, false otherwise
     */
    public boolean isTokenExpired(Map<String, Object> decodedToken) {
        try {
            Object expObj = decodedToken.get("exp");
            if (expObj instanceof Number) {
                long exp = ((Number) expObj).longValue();
                long currentTime = System.currentTimeMillis() / 1000;
                return currentTime > exp;
            }
            return true; // Assume expired if exp claim is missing or invalid
        } catch (Exception e) {
            log.error("Error checking token expiration: {}", e.getMessage());
            return true; // Assume expired on error
        }
    }
}