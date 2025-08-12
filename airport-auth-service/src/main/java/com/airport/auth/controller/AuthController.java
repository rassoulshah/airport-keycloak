package com.airport.auth.controller;

import com.airport.auth.dto.LoginRequest;
import com.airport.auth.dto.LoginResponse;
import com.airport.auth.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        try {
            LoginResponse response = authService.login(loginRequest.getUsername(), loginRequest.getPassword());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                new LoginResponse(null, "Invalid credentials", null, null)
            );
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@RequestBody String refreshToken) {
        try {
            LoginResponse response = authService.refreshToken(refreshToken);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                new LoginResponse(null, "Invalid refresh token", null, null)
            );
        }
    }
}