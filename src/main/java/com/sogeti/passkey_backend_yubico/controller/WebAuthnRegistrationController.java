package com.sogeti.passkey_backend_yubico.controller;

import com.sogeti.passkey_backend_yubico.model.RegistrationRequestDto;
import com.sogeti.passkey_backend_yubico.repository.InMemoryCredentialRepository;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.UserIdentity;
import jakarta.servlet.http.HttpSession;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.RegisteredCredential;
import java.security.SecureRandom;
import java.util.Optional;
import org.springframework.web.bind.annotation.CrossOrigin;

import static com.sogeti.passkey_backend_yubico.utils.ByteUtils.generateRandom;

@RestController
@RequestMapping("/webauthn/register")
@CrossOrigin(origins = "http://localhost:5500", allowCredentials = "true")
public class WebAuthnRegistrationController {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(WebAuthnRegistrationController.class);
    private final RelyingParty relyingParty;
    private final InMemoryCredentialRepository credentialRepository;
    private final SecureRandom random = new SecureRandom();

    private static final String SESSION_REGISTRATION_OPTIONS = "webauthn_registration_options";
    private static final String SESSION_REGISTRATION_USERNAME = "webauthn_registration_username";
    private static final String SESSION_AUTHENTICATED_USER = "authenticated_username";


    @Autowired
    public WebAuthnRegistrationController(RelyingParty relyingParty, InMemoryCredentialRepository credentialRepository) {
        this.relyingParty = relyingParty;
        this.credentialRepository = credentialRepository;
    }

    @PostMapping("/start")
    public ResponseEntity<String> startRegistration(@RequestBody RegistrationRequestDto registrationRequest, HttpSession session) {

        // Check if this is an authenticated user adding a new passkey
        String authenticatedUsername = (String) session.getAttribute(SESSION_AUTHENTICATED_USER);
        String addPasskeyUsername = (String) session.getAttribute("add_passkey_username");

        boolean isAddingPasskey = authenticatedUsername != null && addPasskeyUsername != null;

        if (isAddingPasskey) {
            // For adding passkeys, use the authenticated username
            String username = authenticatedUsername;
            logger.info("Authenticated user {} is adding a new passkey", username);

            try {
                Optional<UserIdentity> existingUserOpt = credentialRepository.getUserByUsername(username);
                if (existingUserOpt.isEmpty()) {
                    logger.error("Authenticated user {} not found in repository", username);
                    return ResponseEntity.status(500).body("{\"error\":\"User not found\"}");
                }

                UserIdentity userIdentity = existingUserOpt.get();

                StartRegistrationOptions registrationOptions = StartRegistrationOptions.builder()
                        .user(userIdentity)
                        .build();

                PublicKeyCredentialCreationOptions credentialCreationOptions = relyingParty.startRegistration(registrationOptions);

                session.setAttribute(SESSION_REGISTRATION_OPTIONS, credentialCreationOptions.toJson());
                session.setAttribute(SESSION_REGISTRATION_USERNAME, username);
                logger.info("Registration options generated for adding passkey to {}. Stored in session.", username);

                String JSONResponse = credentialCreationOptions.toCredentialsCreateJson();
                return ResponseEntity.ok(JSONResponse);

            } catch (Exception e) {
                logger.error("Error during startRegistration for adding passkey to user: {}", username, e);
                return ResponseEntity.status(500).body(null);
            }
        } else {
            // Original registration flow for new users
            if (registrationRequest == null || registrationRequest.getUsername() == null || registrationRequest.getUsername().isBlank()) {
                logger.warn("Registration start request received with missing username.");
                return ResponseEntity.badRequest().body("{\"error\":\"Username is required.\"}");
            }
            if (registrationRequest.getDisplayName() == null || registrationRequest.getDisplayName().isBlank()) {
                logger.warn("Registration start request received with missing displayName for username: {}", registrationRequest.getUsername());
                return ResponseEntity.badRequest().body("{\"error\":\"Display name is required.\"}");
            }

            String username = registrationRequest.getUsername();
            String displayName = registrationRequest.getDisplayName();
            logger.info("Attempting to start registration for username: {}", username);

            try {
                UserIdentity userIdentity;

                Optional<UserIdentity> existingUserOpt = credentialRepository.getUserHandleForUsername(username)
                        .map(handle -> UserIdentity.builder()
                                .name(username)
                                .displayName(displayName)
                                .id(handle)
                                .build()
                        );

                if (existingUserOpt.isPresent()) {
                    userIdentity = existingUserOpt.get();
                    logger.info("Existing user found for registration: {}", username);
                } else {
                    logger.info("User {} not found, creating new user.", username);
                    ByteArray newUserHandle = generateRandom(64);

                    userIdentity = credentialRepository.createUser(username, displayName, newUserHandle);
                    logger.info("New user {} created with handle: {}", username, newUserHandle.getBase64Url());
                }

                StartRegistrationOptions registrationOptions = StartRegistrationOptions.builder()
                        .user(userIdentity)
                        .build();

                PublicKeyCredentialCreationOptions credentialCreationOptions = relyingParty.startRegistration(registrationOptions);

                session.setAttribute(SESSION_REGISTRATION_OPTIONS, credentialCreationOptions.toJson());
                session.setAttribute(SESSION_REGISTRATION_USERNAME, username);
                logger.info("Registration options generated for {}. Stored in session.", username);

                String JSONResponse = credentialCreationOptions.toCredentialsCreateJson();
                logger.debug("Sending credential creation options to client for {}: {}", username, JSONResponse);
                return ResponseEntity.ok(JSONResponse);

            } catch (Exception e) {
                logger.error("Error during startRegistration for username: {}", username, e);
                return ResponseEntity.status(500).body(null);
            }
        }
    }

    @PostMapping("/finish")
    public ResponseEntity<?> finishRegistration(@RequestBody String publicKeyCredentialJson, HttpSession session) {

        logger.info("Received registration finish request");

        String username = (String) session.getAttribute(SESSION_REGISTRATION_USERNAME);
        String credentialCreationOptionsJson = (String) session.getAttribute(SESSION_REGISTRATION_OPTIONS);
        String authenticatedUsername = (String) session.getAttribute(SESSION_AUTHENTICATED_USER);
        boolean isAddingPasskey = authenticatedUsername != null && username != null && username.equals(authenticatedUsername);

        if (username == null || credentialCreationOptionsJson == null) {
            logger.warn("No registration session found");
            return ResponseEntity.badRequest().body("{\"error\":\"Registration session expired or invalid\"}");
        }

        try {
            PublicKeyCredentialCreationOptions request = PublicKeyCredentialCreationOptions.fromJson(credentialCreationOptionsJson);

            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc =
                    PublicKeyCredential.parseRegistrationResponseJson(publicKeyCredentialJson);

            RegistrationResult result = relyingParty.finishRegistration(FinishRegistrationOptions.builder()
                    .request(request)
                    .response(pkc)
                    .build());

            Optional<ByteArray> userHandleOpt = credentialRepository.getUserHandleForUsername(username);
            if (userHandleOpt.isEmpty()) {
                logger.error("User handle not found for username: {}", username);
                return ResponseEntity.status(500).body("{\"error\":\"User not found\"}");
            }

            ByteArray userHandle = userHandleOpt.get();
            RegisteredCredential credential = RegisteredCredential.builder()
                    .credentialId(result.getKeyId().getId())
                    .userHandle(userHandle)
                    .publicKeyCose(result.getPublicKeyCose())
                    .signatureCount(result.getSignatureCount())
                    .build();

            Optional<UserIdentity> userIdentityOpt = credentialRepository.getUserByUsername(username);

            if (userIdentityOpt.isEmpty()) {
                logger.error("User identity not found for username: {}", username);
                return ResponseEntity.status(500).body("{\"error\":\"User not found\"}");
            }

            credentialRepository.addCredential(userIdentityOpt.get(), credential);

            session.removeAttribute(SESSION_REGISTRATION_OPTIONS);
            session.removeAttribute(SESSION_REGISTRATION_USERNAME);
            session.removeAttribute("add_passkey_username");

            if (isAddingPasskey) {
                logger.info("Passkey added successfully for authenticated user: {}", username);
                return ResponseEntity.ok("{\"success\":true,\"username\":\"" + username + "\",\"isAddingPasskey\":true}");
            } else {
                logger.info("Registration completed successfully for user: {}", username);
                return ResponseEntity.ok("{\"success\":true,\"username\":\"" + username + "\"}");
            }

        } catch (Exception e) {
            logger.error("Error during finishRegistration: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body("{\"error\":\"" + e.getMessage() + "\"}");
        }
    }
}