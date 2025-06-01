package com.sogeti.passkey_backend_yubico.model;

public class RegistrationRequestDto {
    private String username;
    private String displayName;

    public RegistrationRequestDto() {
    }

    public RegistrationRequestDto(String username, String displayName) {
        this.username = username;
        this.displayName = displayName;
    }

    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }
}