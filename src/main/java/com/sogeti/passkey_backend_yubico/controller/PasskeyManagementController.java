package com.sogeti.passkey_backend_yubico.controller;

import com.sogeti.passkey_backend_yubico.model.PasskeyInfoDto;
import com.sogeti.passkey_backend_yubico.repository.InMemoryCredentialRepository;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/passkeys")
@CrossOrigin(origins = "http://localhost:5500", allowCredentials = "true")
public class PasskeyManagementController {

    private static final Logger logger = LoggerFactory.getLogger(PasskeyManagementController.class);
    private static final String SESSION_AUTHENTICATED_USER = "authenticated_username";

    private final InMemoryCredentialRepository credentialRepository;

    @Autowired
    public PasskeyManagementController(InMemoryCredentialRepository credentialRepository) {
        this.credentialRepository = credentialRepository;
    }

    @GetMapping
    public ResponseEntity<?> getUserPasskeys(HttpSession session) {
        String authenticatedUsername = (String) session.getAttribute(SESSION_AUTHENTICATED_USER);

        if (authenticatedUsername == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }

        try {
            List<PasskeyInfoDto> passkeys = credentialRepository.getPasskeysForUser(authenticatedUsername);
            logger.info("Retrieved {} passkeys for user: {}", passkeys.size(), authenticatedUsername);
            return ResponseEntity.ok(passkeys);
        } catch (Exception e) {
            logger.error("Error retrieving passkeys for user: {}", authenticatedUsername, e);
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        }
    }

    @PutMapping("/{passkeyId}/name")
    public ResponseEntity<?> updatePasskeyName(@PathVariable String passkeyId, @RequestBody Map<String, String> request, HttpSession session) {

        String authenticatedUsername = (String) session.getAttribute(SESSION_AUTHENTICATED_USER);

        if (authenticatedUsername == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }

        String newName = request.get("name");
        if (newName == null || newName.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Name is required"));
        }

        try {
            boolean updated = credentialRepository.updatePasskeyName(authenticatedUsername, passkeyId, newName.trim());

            if (updated) {
                logger.info("Passkey name updated for user: {} passkeyId: {}", authenticatedUsername, passkeyId);
                return ResponseEntity.ok(Map.of("success", true, "message", "Passkey name updated successfully"));
            } else {
                return ResponseEntity.status(404).body(Map.of("error", "Passkey not found"));
            }
        } catch (Exception e) {
            logger.error("Error updating passkey name for user: {}", authenticatedUsername, e);
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        }
    }

    @DeleteMapping("/{passkeyId}")
    public ResponseEntity<?> deletePasskey(
            @PathVariable String passkeyId,
            HttpSession session) {

        String authenticatedUsername = (String) session.getAttribute(SESSION_AUTHENTICATED_USER);

        if (authenticatedUsername == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }

        try {
            // Check if user has more than 1 passkey before deletion
            List<PasskeyInfoDto> userPasskeys = credentialRepository.getPasskeysForUser(authenticatedUsername);
            if (userPasskeys.size() <= 1) {
                return ResponseEntity.badRequest().body(Map.of("error", "Cannot delete the last passkey. You must have at least one passkey to access your account."));
            }

            boolean deleted = credentialRepository.deletePasskey(authenticatedUsername, passkeyId);

            if (deleted) {
                logger.info("Passkey deleted for user: {} passkeyId: {}", authenticatedUsername, passkeyId);
                return ResponseEntity.ok(Map.of("success", true, "message", "Passkey deleted successfully"));
            } else {
                return ResponseEntity.status(404).body(Map.of("error", "Passkey not found"));
            }
        } catch (Exception e) {
            logger.error("Error deleting passkey for user: {}", authenticatedUsername, e);
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        }
    }

    // New endpoint to initiate adding a new passkey
    @PostMapping("/add/start")
    public ResponseEntity<?> startAddPasskey(HttpSession session) {
        String authenticatedUsername = (String) session.getAttribute(SESSION_AUTHENTICATED_USER);

        if (authenticatedUsername == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }

        try {
            session.setAttribute("add_passkey_username", authenticatedUsername);
            logger.info("Started add passkey flow for user: {}", authenticatedUsername);
            return ResponseEntity.ok(Map.of("success", true, "username", authenticatedUsername));
        } catch (Exception e) {
            logger.error("Error starting add passkey flow for user: {}", authenticatedUsername, e);
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        }
    }
}