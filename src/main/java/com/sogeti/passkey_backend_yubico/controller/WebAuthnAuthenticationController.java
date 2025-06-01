package com.sogeti.passkey_backend_yubico.controller;

import com.sogeti.passkey_backend_yubico.repository.InMemoryCredentialRepository;
import com.sogeti.passkey_backend_yubico.model.AuthenticationRequestDto;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.exception.AssertionFailedException;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/webauthn/authentication")
@CrossOrigin(origins = "http://localhost:5500", allowCredentials = "true")
public class WebAuthnAuthenticationController {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnAuthenticationController.class);
    private static final String SESSION_AUTHENTICATED_USER = "authenticated_username";

    private final RelyingParty relyingParty;
    private final InMemoryCredentialRepository credentialRepository;

    private static final String SESSION_AUTHENTICATION_REQUEST = "webauthn_authentication_request";

    @Autowired
    public WebAuthnAuthenticationController(RelyingParty relyingParty, InMemoryCredentialRepository credentialRepository) {
        this.relyingParty = relyingParty;
        this.credentialRepository = credentialRepository;
    }

    @PostMapping("/start")
    public ResponseEntity<String> startAuthentication(@RequestBody(required = false) AuthenticationRequestDto authRequest, HttpSession session) {

        String username = (authRequest != null) ? authRequest.getUsername() : null;
        logger.info("Attempting to start authentication for username: {}", username != null ? username : "[discoverable/passkey]");

        try {
            StartAssertionOptions.StartAssertionOptionsBuilder optionsBuilder = StartAssertionOptions.builder();
            if (username != null && !username.isBlank()) {

                if (credentialRepository.getUserHandleForUsername(username).isEmpty()) {
                    logger.warn("Attempt to start authentication for non-existent user: {}", username);
                }
                optionsBuilder.username(username);
            }

            AssertionRequest assertionRequest = relyingParty.startAssertion(optionsBuilder.build());

            session.setAttribute(SESSION_AUTHENTICATION_REQUEST, assertionRequest.toJson());
            logger.info("Authentication options generated for {}. Stored in session.", username != null ? username : "[discoverable]");

            String jsonResponse = assertionRequest.toCredentialsGetJson();
            logger.debug("Sending assertion request to client for {}: {}", username != null ? username : "[discoverable]", jsonResponse);
            return ResponseEntity.ok(jsonResponse);

        } catch (Exception e) {
            logger.error("Error during startAuthentication for username: {}", username != null ? username : "[discoverable]", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\":\"An internal error occurred: " + e.getMessage().replace("\"", "'") + "\"}");
        }
    }

    @PostMapping("/finish")
    public ResponseEntity<String> finishAuthentication(
            @RequestBody String publicKeyCredentialJson,
            HttpSession session) {

        logger.info("Attempting to finish authentication with response: {}", publicKeyCredentialJson);

        String assertionRequestJson = (String) session.getAttribute(SESSION_AUTHENTICATION_REQUEST);
        if (assertionRequestJson == null) {
            logger.warn("No authentication request found in session or session expired.");
            return ResponseEntity.badRequest().body("{\"error\":\"Authentication timed out or session expired. Please try again.\"}");
        }

        session.removeAttribute(SESSION_AUTHENTICATION_REQUEST);

        try {
            AssertionRequest assertionRequest = AssertionRequest.fromJson(assertionRequestJson);
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc =
                    PublicKeyCredential.parseAssertionResponseJson(publicKeyCredentialJson);

            AssertionResult result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(assertionRequest)
                    .response(pkc)
                    .build());

            if (result.isSuccess()) {
                credentialRepository.updateSignatureCount(
                        result.getUserHandle(),
                        result.getCredential().getCredentialId(),
                        result.getSignatureCount()
                );
                String authenticatedUsername = result.getUsername();
                session.setAttribute(SESSION_AUTHENTICATED_USER, authenticatedUsername);
                logger.info("Authentication successful for user: {}", result.getUsername());
                return ResponseEntity.ok("{\"success\":true, \"username\":\"" + result.getUsername() + "\"}");
            } else {
                logger.warn("Authentication failed for user (username from result if available): {}", result.getUsername());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"success\":false, \"error\":\"Authentication failed. Invalid credentials.\"}");
            }
        } catch (AssertionFailedException e) {
            logger.warn("Assertion failed during authentication: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"success\":false, \"error\":\"Assertion failed: " + e.getMessage().replace("\"", "'") + "\"}");
        } catch (Exception e) {
            logger.error("Unexpected error during finishAuthentication: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"success\":false, \"error\":\"An unexpected error occurred during authentication.\"}");
        }
    }
}
