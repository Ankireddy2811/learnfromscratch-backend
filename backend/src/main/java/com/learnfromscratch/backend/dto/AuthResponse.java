package com.learnfromscratch.backend.dto;

public class AuthResponse {
    private String accessToken;
    private String username;
    private String role;

    public AuthResponse(String accessToken, String username, String role) {
        this.accessToken = accessToken;
        this.username = username;
        this.role = role;
    }

    public String getToken() { return accessToken; }
    public String getUsername() { return username; }
    public String getRole() { return role; }
}
