package com.airport.auth.dto;

public class LoginResponse {
    private String accessToken;
    private String message;
    private String refreshToken;
    private Long expiresIn;

    // Constructors
    public LoginResponse() {}
    
    public LoginResponse(String accessToken, String message, String refreshToken, Long expiresIn) {
        this.accessToken = accessToken;
        this.message = message;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
    }

    // Getters and Setters
    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public String getRefreshToken() { return refreshToken; }
    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
    
    public Long getExpiresIn() { return expiresIn; }
    public void setExpiresIn(Long expiresIn) { this.expiresIn = expiresIn; }
}