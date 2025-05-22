package com.sogeti.passkey_backend_yubico;

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

import java.security.SecureRandom;
import java.util.Optional;
import java.util.logging.Logger;

@RestController
@RequestMapping("/webauthn/register")
public class WebAuthnRegistrationController {

    private static final Logger logger = (Logger) LoggerFactory.getLogger(WebAuthnRegistrationController.class);

    private final RelyingParty relyingParty;
    private final InMemoryCredentialRepository credentialRepository;
    private final SecureRandom random = new SecureRandom();

    // Session attribute keys
    private static final String SESSION_REGISTRATION_OPTIONS = "webauthn_registration_options";
    private static final String SESSION_REGISTRATION_USERNAME = "webauthn_registration_username";


    @Autowired
    public WebAuthnRegistrationController(RelyingParty relyingParty, InMemoryCredentialRepository credentialRepository) {
        this.relyingParty = relyingParty;
        this.credentialRepository = credentialRepository;
    }

    @PostMapping("/start")
    public ResponseEntity<String> startRegistration( @RequestBody RegistrationRequestDto registrationRequest, HttpSession session) {

        if (registrationRequest == null || registrationRequest.getUsername() == null || registrationRequest.getUsername().isBlank()) {
            logger.warning("Registration start request received with missing username.");
            return ResponseEntity.badRequest().body("{\"error\":\"Username is required.\"}");
        }
        if (registrationRequest.getDisplayName() == null || registrationRequest.getDisplayName().isBlank()) {
            logger.warning("Registration start request received with missing displayName for username: {}");
            return ResponseEntity.badRequest().body("{\"error\":\"Display name is required.\"}");
        }

        String username = registrationRequest.getUsername();
        String displayName = registrationRequest.getDisplayName();
        logger.info("Attempting to start registration for username: {}" + username);

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
                logger.info("Existing user found for registration: " + username);
            } else {
                logger.info("User {" + username + "} not found, creating new user.");
                byte[] userHandleBytes = new byte[64];
                random.nextBytes(userHandleBytes);
                ByteArray newUserHandle = new ByteArray(userHandleBytes);

                userIdentity = credentialRepository.createUser(username, displayName, newUserHandle);
                logger.info("New user {" + username + "} created with handle: " + newUserHandle.getBase64Url());
            }

            StartRegistrationOptions registrationOptions = StartRegistrationOptions.builder()
                    .user(userIdentity)
                    .build();

            PublicKeyCredentialCreationOptions credentialCreationOptions = relyingParty.startRegistration(registrationOptions);

            session.setAttribute(SESSION_REGISTRATION_OPTIONS, credentialCreationOptions.toJson());
            session.setAttribute(SESSION_REGISTRATION_USERNAME, username);
            logger.info("Registration options generated for {" + username + "}. Stored in session.");

            String JSONResponse = credentialCreationOptions.toCredentialsCreateJson();
            logger.info("Sending credential creation options to client for" + username + ": " + JSONResponse);
            return ResponseEntity.ok(JSONResponse);

        } catch (Exception e) {
            logger.info("Error during startRegistration for username: {}" + username + ". Error:" + e);
            return null;
        }
    }
}