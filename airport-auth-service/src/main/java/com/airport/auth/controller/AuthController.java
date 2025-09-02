package com.airport.auth.controller;

import com.airport.auth.dto.RegisterRequest;
import com.airport.auth.service.KeycloakService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final KeycloakService keycloakService;

    public AuthController(KeycloakService keycloakService) {
        this.keycloakService = keycloakService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        // server-side validation is done via @Valid
        try {
            // Optional: pre-check for email duplicates to return 409 quickly
            if (keycloakService.emailExists(request.getEmail())) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "email already registered"));
            }

            URI location = keycloakService.createUser(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("status", "ok", "location", location != null ? location.toString() : null));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "unexpected error"));
        }
    }
}
