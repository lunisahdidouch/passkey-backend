package com.sogeti.passkey_backend_yubico; // Or your appropriate package

public class RegistrationRequestDto {
    private String username;
    private String displayName;

    // Constructors (optional, but can be useful)
    public RegistrationRequestDto() {
    }

    public RegistrationRequestDto(String username, String displayName) {
        this.username = username;
        this.displayName = displayName;
    }

    // Getters
    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName;
    }

    // Setters (needed if you want Spring/Jackson to set properties after default construction)
    public void setUsername(String username) {
        this.username = username;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }
}