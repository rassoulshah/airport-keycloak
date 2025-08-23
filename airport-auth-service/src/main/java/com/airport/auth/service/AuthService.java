package com.airport.auth.service;

import com.airport.auth.dto.AuthResponse;
import com.airport.auth.dto.LoginRequest;
import com.airport.auth.dto.RegisterRequest;
import com.airport.auth.user.User;
import com.airport.auth.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;

    @Transactional
    public AuthResponse register(RegisterRequest req) {
        if (users.existsByUsername(req.getUsername()))
            throw new IllegalArgumentException("username taken");
        if (users.existsByEmail(req.getEmail()))
            throw new IllegalArgumentException("email taken");

        User u = User.builder()
                .username(req.getUsername())
                .email(req.getEmail())
                .password(encoder.encode(req.getPassword()))
                .roles("ROLE_USER")
                .build();
        users.save(u);

        String token = jwt.generateToken(u.getId(), u.getUsername(), u.getRoles());
        return new AuthResponse(token, 60L * 60L, "Bearer");
    }

    public AuthResponse login(LoginRequest req) {
        User u = users.findByUsername(req.getUsername())
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
        if (!encoder.matches(req.getPassword(), u.getPassword()))
            throw new BadCredentialsException("Invalid credentials");

        String token = jwt.generateToken(u.getId(), u.getUsername(), u.getRoles());
        return new AuthResponse(token, 60L * 60L, "Bearer");
    }
}
