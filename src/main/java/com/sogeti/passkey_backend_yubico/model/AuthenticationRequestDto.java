package com.sogeti.passkey_backend_yubico.model;

public class AuthenticationRequestDto {
    private String username;

    public AuthenticationRequestDto() {
    }

    public AuthenticationRequestDto(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
