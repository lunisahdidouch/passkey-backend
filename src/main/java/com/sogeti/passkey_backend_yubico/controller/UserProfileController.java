package com.sogeti.passkey_backend_yubico.controller;

import com.sogeti.passkey_backend_yubico.repository.InMemoryCredentialRepository;
import com.yubico.webauthn.data.UserIdentity;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/user")
@CrossOrigin(origins = "http://localhost:5500", allowCredentials = "true")
public class UserProfileController {

    private static final Logger logger = LoggerFactory.getLogger(UserProfileController.class);
    private final InMemoryCredentialRepository credentialRepository;

    private static final String SESSION_AUTHENTICATED_USER = "authenticated_username";

    @Autowired
    public UserProfileController(InMemoryCredentialRepository credentialRepository) {
        this.credentialRepository = credentialRepository;
    }


    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(HttpSession session) {
        logger.info("Profile request received, session ID: {}", session.getId());

        String authenticatedUsername = (String) session.getAttribute(SESSION_AUTHENTICATED_USER);
        logger.info("Authenticated user: {}", authenticatedUsername);
        if (authenticatedUsername == null || authenticatedUsername.trim().isEmpty()) {
            logger.warn("Unauthorized profile access attempt - no authenticated session");
            return ResponseEntity.status(401).body(createErrorResponse("Not authenticated"));
        }

        try {
            Optional<UserIdentity> userIdentityOpt = credentialRepository.getUserByUsername(authenticatedUsername);

            if (userIdentityOpt.isEmpty()) {
                logger.error("Authenticated user {} not found in repository", authenticatedUsername);
                session.removeAttribute(SESSION_AUTHENTICATED_USER);
                return ResponseEntity.status(401).body(createErrorResponse("User not found"));
            }

            UserIdentity userIdentity = userIdentityOpt.get();

            Map<String, Object> profileData = new HashMap<>();
            profileData.put("username", userIdentity.getName());
            profileData.put("displayName", userIdentity.getDisplayName());
            profileData.put("email", userIdentity.getName());

            logger.info("Profile data successfully returned for user: {}", authenticatedUsername);
            return ResponseEntity.ok(profileData);

        } catch (Exception e) {
            logger.error("Error retrieving profile for user: {}", authenticatedUsername, e);
            return ResponseEntity.status(500).body(createErrorResponse("Internal server error"));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpSession session) {
        String authenticatedUsername = (String) session.getAttribute(SESSION_AUTHENTICATED_USER);

        logger.info("Logout request received for session: {}", session.getId());

        if (authenticatedUsername != null) {
            logger.info("Logging out authenticated user: {}", authenticatedUsername);
            session.removeAttribute(SESSION_AUTHENTICATED_USER);
        }

        try {
            session.invalidate();
            logger.info("Session invalidated successfully");
        } catch (IllegalStateException e) {
            logger.debug("Session was already invalidated");
        }

        return ResponseEntity.ok(Map.of("success", true, "message", "Logged out successfully"));
    }

    @GetMapping("/auth-status")
    public ResponseEntity<?> getAuthStatus(HttpSession session) {
        String authenticatedUsername = (String) session.getAttribute(SESSION_AUTHENTICATED_USER);

        if (authenticatedUsername != null && credentialRepository.userExists(authenticatedUsername)) {
            return ResponseEntity.ok(Map.of(
                    "authenticated", true,
                    "username", authenticatedUsername
            ));
        } else {
            if (authenticatedUsername != null) {
                session.removeAttribute(SESSION_AUTHENTICATED_USER);
            }
            return ResponseEntity.status(401).body(Map.of(
                    "authenticated", false,
                    "error", "Not authenticated"
            ));
        }
    }

    private Map<String, String> createErrorResponse(String message) {
        Map<String, String> error = new HashMap<>();
        error.put("error", message);
        return error;
    }
}