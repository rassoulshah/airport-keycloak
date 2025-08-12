package com.airport.auth.service;

import com.airport.auth.dto.LoginResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

@Service
public class AuthService {

    @Value("${keycloak.auth-server-url}")
    private String keycloakServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    private final WebClient webClient;

    public AuthService() {
        this.webClient = WebClient.builder().build();
    }

    public LoginResponse login(String username, String password) {
        String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token",
                keycloakServerUrl, realm);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "password");
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);
        formData.add("username", username);
        formData.add("password", password);

        try {
            Mono<Map> responseMono = webClient.post()
                    .uri(tokenUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData(formData))
                    .retrieve()
                    .bodyToMono(Map.class);

            Map<String, Object> response = responseMono.block();

            if (response != null && response.containsKey("access_token")) {
                return new LoginResponse(
                        (String) response.get("access_token"),
                        "Login successful",
                        (String) response.get("refresh_token"),
                        ((Number) response.get("expires_in")).longValue()
                );
            }
        } catch (Exception e) {
            throw new RuntimeException("Authentication failed: " + e.getMessage());
        }

        throw new RuntimeException("Authentication failed");
    }

    public LoginResponse refreshToken(String refreshToken) {
        String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token",
                keycloakServerUrl, realm);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "refresh_token");
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);
        formData.add("refresh_token", refreshToken);

        try {
            Mono<Map> responseMono = webClient.post()
                    .uri(tokenUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData(formData))
                    .retrieve()
                    .bodyToMono(Map.class);

            Map<String, Object> response = responseMono.block();

            if (response != null && response.containsKey("access_token")) {
                return new LoginResponse(
                        (String) response.get("access_token"),
                        "Token refreshed successfully",
                        (String) response.get("refresh_token"),
                        ((Number) response.get("expires_in")).longValue()
                );
            }
        } catch (Exception e) {
            throw new RuntimeException("Token refresh failed: " + e.getMessage());
        }

        throw new RuntimeException("Token refresh failed");
    }
}