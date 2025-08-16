package com.airport.auth.service;

import com.airport.auth.dto.RegisterRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
public class KeycloakService {

    private final RestTemplate restTemplate;

    @Value("${keycloak.url}")
    private String keycloakUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client.id}")
    private String clientId;

    @Value("${keycloak.client.secret}")
    private String clientSecret;

    public KeycloakService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    // Obtain service token using client_credentials
    public String obtainServiceToken() {
        String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", keycloakUrl, realm);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "client_credentials");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> resp = restTemplate.exchange(tokenUrl, HttpMethod.POST, request, Map.class);
        if (!resp.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to get keycloak token: " + resp.getStatusCode());
        }
        Map<String, Object> data = resp.getBody();
        return (String) data.get("access_token");
    }

    // Create user in Keycloak
    public URI createUser(RegisterRequest req) {
        String adminUrl = String.format("%s/admin/realms/%s/users", keycloakUrl, realm);
        String token = obtainServiceToken();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);

        Map<String, Object> credential = Map.of(
                "type", "password",
                "value", req.getPassword(),
                "temporary", false
        );

        Map<String, Object> payload = new HashMap<>();
        payload.put("username", req.getEmail());
        payload.put("email", req.getEmail());
        payload.put("firstName", req.getName());
        payload.put("enabled", true);
        payload.put("credentials", List.of(credential));

        HttpEntity<Object> entity = new HttpEntity<>(payload, headers);

        try {
            ResponseEntity<Void> response = restTemplate.exchange(adminUrl, HttpMethod.POST, entity, Void.class);
            if (response.getStatusCode() == HttpStatus.CREATED) {
                return response.getHeaders().getLocation();
            } else {
                throw new RuntimeException("Keycloak create user failed: " + response.getStatusCode());
            }
        } catch (HttpClientErrorException.Conflict conflict) {
            throw new RuntimeException("email/username already exists");
        }
    }

    // Optional helper: check existing users by email (if you want pre-check)
    public boolean emailExists(String email) {
        String token = obtainServiceToken();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        String url = String.format("%s/admin/realms/%s/users?email=%s", keycloakUrl, realm, URLEncoder.encode(email, StandardCharsets.UTF_8));
        ResponseEntity<List> resp = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), List.class);
        List body = resp.getBody();
        return body != null && !body.isEmpty();
    }
}
