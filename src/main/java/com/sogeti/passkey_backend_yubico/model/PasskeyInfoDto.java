package com.sogeti.passkey_backend_yubico.model;

import java.time.LocalDateTime;

public class PasskeyInfoDto {
    private String id;
    private String name;
    private LocalDateTime createdAt;
    private LocalDateTime lastUsed;

    public PasskeyInfoDto() {
    }

    public PasskeyInfoDto(String id, String name, LocalDateTime createdAt, LocalDateTime lastUsed) {
        this.id = id;
        this.name = name;
        this.createdAt = createdAt;
        this.lastUsed = lastUsed;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getLastUsed() { return lastUsed; }
    public void setLastUsed(LocalDateTime lastUsed) { this.lastUsed = lastUsed; }
}