package com.airport.api.gateway.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // enable CORS support (uses corsConfigurationSource bean below)
            .cors()
            .and()

            // disable CSRF for a stateless JWT API
            .csrf().disable()

            // do not create HTTP session — we're stateless with JWTs
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()

            .authorizeHttpRequests(auth -> auth
                // allow CORS preflight (OPTIONS) for any path
                .requestMatchers(new AntPathRequestMatcher("/**", "OPTIONS")).permitAll()

                // allow some public endpoints
                .requestMatchers(new AntPathRequestMatcher("/actuator/**")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/swagger-ui/**")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/v3/api-docs/**")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/public/**")).permitAll()

                // everything else must be authenticated
                .anyRequest().authenticated()
            )

            // validate JWTs in Authorization: Bearer <token>
            .oauth2ResourceServer(oauth2 -> oauth2.jwt());

        return http.build();
    }

    /**
     * Basic permissive CORS configuration suitable for local development.
     * Adjust origins/allowed headers/credentials for production.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(List.of("*")); // <- change to specific origins in prod
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        cfg.setAllowedHeaders(List.of("*"));
        cfg.setExposedHeaders(List.of("Authorization", "Content-Disposition"));
        cfg.setAllowCredentials(false);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }
}
